use std::os::unix::process::ExitStatusExt;
use std::process::{ExitStatus, Output};

use super::*;

#[test]
fn stale_socket_recheck_rejects_replaced_inode() {
    let dir = tempfile::TempDir::new().unwrap();
    let s1 = dir.path().join("s1.sock");
    let s2 = dir.path().join("s2.sock");
    let _l1 = UnixListener::bind(&s1).unwrap();
    let _l2 = UnixListener::bind(&s2).unwrap();

    let meta1 = fs::symlink_metadata(&s1).unwrap();
    let meta2 = fs::symlink_metadata(&s2).unwrap();
    assert!(verify_stale_socket_unchanged(&s1, &meta1, meta1.dev(), meta1.ino()).is_ok());

    let err = verify_stale_socket_unchanged(&s1, &meta2, meta1.dev(), meta1.ino()).unwrap_err();
    assert!(matches!(err, DaemonError::SocketAlreadyActive(_)));
}

#[test]
fn ancestor_ownership_allows_root_or_parent_owner_and_rejects_third_party() {
    assert!(verify_ancestor_owner(Path::new("/"), 0, 1000).is_ok());
    assert!(verify_ancestor_owner(Path::new("/home/alice"), 1000, 1000).is_ok());
    assert!(verify_ancestor_owner(Path::new("/"), 0, 0).is_ok());

    let third_party = verify_ancestor_owner(Path::new("/home/mallory"), 2000, 1000).unwrap_err();
    assert!(matches!(
        third_party,
        DaemonError::UntrustedAncestorOwner {
            ancestor_uid: 2000,
            expected_uid: 1000,
            ..
        }
    ));
    let rendered = third_party.to_string();
    assert!(rendered.contains("owned by uid 2000"));
    assert!(rendered.contains("expected root or daemon euid 1000"));

    let non_root_above_root = verify_ancestor_owner(Path::new("/var/other"), 1000, 0).unwrap_err();
    assert!(matches!(
        non_root_above_root,
        DaemonError::UntrustedAncestorOwner {
            ancestor_uid: 1000,
            expected_uid: 0,
            ..
        }
    ));
}

#[test]
fn deadline_stream_writer_and_reader_share_single_overall_budget() {
    let (a, _b) = UnixStream::pair().unwrap();

    // 1. Expired deadline fails immediately on write without blocking.
    let expired = Instant::now().checked_sub(Duration::from_millis(1));
    let mut expired_writer = DeadlineStreamWriter::with_clock(&a, expired, SystemDeadlineClock);
    let err = expired_writer.write(b"hello").unwrap_err();
    assert_eq!(err.kind(), io::ErrorKind::TimedOut);

    // 2. Unbounded deadline writes and flushes cleanly.
    let mut unbounded_writer = DeadlineStreamWriter::with_clock(&a, None, SystemDeadlineClock);
    assert_eq!(unbounded_writer.write(b"ok").unwrap(), 2);
    unbounded_writer.flush().unwrap();

    // 3. Shared deadline (100ms): after writing and sleeping 60ms, the reader only receives
    // the remaining ~40ms rather than a fresh 100ms timeout.
    let started = Instant::now();
    let shared_deadline = started.checked_add(Duration::from_millis(100));
    let mut shared_writer =
        DeadlineStreamWriter::with_clock(&a, shared_deadline, SystemDeadlineClock);
    shared_writer.write_all(b"ping").unwrap();
    std::thread::sleep(Duration::from_millis(60));
    let mut shared_reader =
        DeadlineStreamReader::with_clock(&a, shared_deadline, SystemDeadlineClock);
    let mut buf = [0u8; 8];
    let read_err = shared_reader.read(&mut buf).unwrap_err();
    let total_elapsed = started.elapsed();
    assert!(
        matches!(
            read_err.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ),
        "expected TimedOut/WouldBlock, got {read_err:?}"
    );
    assert!(
        total_elapsed < Duration::from_millis(160),
        "write+read must share one 100ms budget, elapsed {total_elapsed:?}"
    );

    // 4. Stalled peer (never draining buffer): DeadlineStreamWriter aborts within overall deadline.
    let (sender, _stalled_receiver) = UnixStream::pair().unwrap();
    let write_start = Instant::now();
    let mut bounded_writer = DeadlineStreamWriter::with_clock(
        &sender,
        write_start.checked_add(Duration::from_millis(60)),
        SystemDeadlineClock,
    );
    let block = [0x55u8; 16_384];
    let mut write_err = None;
    for _ in 0..256 {
        if let Err(err) = bounded_writer.write_all(&block) {
            write_err = Some(err);
            break;
        }
    }
    let write_err = write_err.expect("filling stalled UnixStream must hit write deadline");
    assert!(
        matches!(
            write_err.kind(),
            io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
        ),
        "expected TimedOut/WouldBlock on stalled write, got {write_err:?}"
    );
    assert!(
        write_start.elapsed() < Duration::from_millis(200),
        "stalled write must abort within 60ms deadline, elapsed {:?}",
        write_start.elapsed()
    );
}

type PostBindHook = Box<dyn FnMut(&Path) -> Result<PostBindMeta, DaemonError>>;
type ChmodHook = Box<dyn FnMut(&Path, u32) -> Result<(), DaemonError>>;
type EuidHook = Box<dyn Fn() -> Result<u32, DaemonError>>;

struct MockBindOps {
    euid: u32,
    cwd: Option<PathBuf>,
    euid_hook: Option<EuidHook>,
    dir_overrides: Vec<(PathBuf, DirPrefixInfo)>,
    post_bind_results: std::cell::RefCell<Vec<Result<PostBindMeta, DaemonError>>>,
    post_bind_hook: std::cell::RefCell<Option<PostBindHook>>,
    chmod_err: Option<io::ErrorKind>,
    chmod_hook: std::cell::RefCell<Option<ChmodHook>>,
    chmod_calls: std::cell::Cell<usize>,
}

impl MockBindOps {
    fn new(euid: u32) -> Self {
        Self {
            euid,
            cwd: None,
            euid_hook: None,
            dir_overrides: Vec::new(),
            post_bind_results: std::cell::RefCell::new(Vec::new()),
            post_bind_hook: std::cell::RefCell::new(None),
            chmod_err: None,
            chmod_hook: std::cell::RefCell::new(None),
            chmod_calls: std::cell::Cell::new(0),
        }
    }
}

impl SocketBindOps for MockBindOps {
    fn current_dir(&self) -> io::Result<PathBuf> {
        match &self.cwd {
            Some(path) => Ok(path.clone()),
            None => RealSocketBindOps.current_dir(),
        }
    }

    fn current_euid(&self) -> Result<u32, DaemonError> {
        if let Some(hook) = &self.euid_hook {
            return hook();
        }
        Ok(self.euid)
    }

    fn inspect_dir(&self, path: &Path) -> Result<DirPrefixInfo, DaemonError> {
        if let Some((_, info)) = self.dir_overrides.iter().find(|(p, _)| p == path) {
            return Ok(*info);
        }
        let mut info = RealSocketBindOps.inspect_dir(path)?;
        if info.uid != 0 {
            info.uid = self.euid;
        }
        Ok(info)
    }

    fn post_bind_metadata(&self, path: &Path) -> Result<PostBindMeta, DaemonError> {
        if let Some(hook) = self.post_bind_hook.borrow_mut().as_mut() {
            return hook(path);
        }
        let mut queue = self.post_bind_results.borrow_mut();
        if !queue.is_empty() {
            return queue.remove(0);
        }
        RealSocketBindOps.post_bind_metadata(path)
    }

    fn set_permissions(&self, path: &Path, mode: u32) -> Result<(), DaemonError> {
        self.chmod_calls.set(self.chmod_calls.get() + 1);
        if let Some(hook) = self.chmod_hook.borrow_mut().as_mut() {
            return hook(path, mode);
        }
        if let Some(kind) = self.chmod_err {
            return Err(DaemonError::Io {
                path: Some(path.to_path_buf()),
                source: io::Error::new(kind, "injected chmod failure"),
            });
        }
        RealSocketBindOps.set_permissions(path, mode)
    }
}

#[test]
fn current_euid_parsers_and_host_lookup_work_and_fail_closed() {
    let sample = b"Name:\thandfest\nUid:\t1000\t2000\t2000\t2000\nGid:\t1000\t1000\n";
    assert_eq!(parse_proc_status_euid(sample), Some(2000));
    assert_eq!(parse_proc_status_euid(b"Name:\tno-uid\n"), None);
    assert_eq!(parse_proc_status_euid(b"Uid:\t1000\n"), None);
    assert_eq!(parse_proc_status_euid(b"Uid:\t1000\tnotnum\n"), None);

    assert_eq!(parse_id_u_output(b"1000\n"), Some(1000));
    assert_eq!(parse_id_u_output(b"notnum\n"), None);
    assert_eq!(parse_id_u_output(&[0xff, 0xfe]), None);

    let host_euid = current_euid().expect("host euid lookup must succeed");
    let dir = tempfile::TempDir::new().unwrap();
    assert_eq!(fs::symlink_metadata(dir.path()).unwrap().uid(), host_euid);
}

#[test]
fn bind_rejects_untrusted_ancestor_and_parent_owners_before_creating_socket() {
    let root = tempfile::TempDir::new().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700)).unwrap();
    let ancestor = canonical_root.join("ancestor");
    let parent = ancestor.join("parent");
    fs::create_dir(&ancestor).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let sock = parent.join("approver.sock");

    // 1. Ancestor owned by uid 2000 above uid 1000 parent (daemon euid 1000) -> rejected before bind.
    let mut ancestor_ops = MockBindOps::new(1000);
    ancestor_ops.dir_overrides.push((
        ancestor.clone(),
        DirPrefixInfo {
            mode: 0o755,
            uid: 2000,
        },
    ));
    ancestor_ops.dir_overrides.push((
        parent.clone(),
        DirPrefixInfo {
            mode: 0o700,
            uid: 1000,
        },
    ));
    let err = BoundSocket::bind_with_ops(&sock, SocketMode::OwnerOnly, &ancestor_ops).unwrap_err();
    assert!(
        matches!(
            err,
            DaemonError::UntrustedAncestorOwner {
                ref path,
                ancestor_uid: 2000,
                expected_uid: 1000,
            } if path == &ancestor
        ),
        "expected UntrustedAncestorOwner for {}, got {err:?}",
        ancestor.display()
    );
    assert!(fs::symlink_metadata(&sock).is_err());

    // 2. Mallory (uid 2000) owns 0700 parent while root daemon (euid 0) binds -> rejected before bind.
    let mut parent_ops = MockBindOps::new(0);
    parent_ops.dir_overrides.push((
        ancestor.clone(),
        DirPrefixInfo {
            mode: 0o755,
            uid: 0,
        },
    ));
    parent_ops.dir_overrides.push((
        parent.clone(),
        DirPrefixInfo {
            mode: 0o700,
            uid: 2000,
        },
    ));
    let err = BoundSocket::bind_with_ops(&sock, SocketMode::OwnerOnly, &parent_ops).unwrap_err();
    assert!(matches!(
        err,
        DaemonError::UntrustedParentOwner {
            ref path,
            parent_uid: 2000,
            expected_uid: 0,
        } if path == &parent
    ));
    assert!(err.to_string().contains("owned by uid 2000"));
    assert!(err.to_string().contains("daemon euid 0"));
    assert!(fs::symlink_metadata(&sock).is_err());
}

#[test]
fn bind_refuses_post_bind_non_socket_or_symlink_and_cleans_up_on_chmod_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    let host_euid = current_euid().unwrap();

    // 1. Post-bind non-socket and symlink metadata must fail before chmod is ever invoked.
    for (name, fake_meta) in [
        (
            "non_socket.sock",
            PostBindMeta {
                is_symlink: false,
                is_socket: false,
                dev: 1,
                ino: 1,
            },
        ),
        (
            "symlink.sock",
            PostBindMeta {
                is_symlink: true,
                is_socket: false,
                dev: 1,
                ino: 2,
            },
        ),
    ] {
        let sock = canonical.join(name);
        let ops = MockBindOps::new(host_euid);
        ops.post_bind_results.borrow_mut().push(Ok(fake_meta));
        let err = BoundSocket::bind_with_ops(&sock, SocketMode::OwnerOnly, &ops).unwrap_err();
        assert!(matches!(err, DaemonError::PathExistsNotSocket(ref p) if p == &sock));
        assert_eq!(ops.chmod_calls.get(), 0, "chmod must not run on bad lstat");
    }

    // 2. Post-bind chmod failure must return Io error AND RAII-unlink the created socket.
    let chmod_sock = canonical.join("chmod_fail.sock");
    let mut chmod_ops = MockBindOps::new(host_euid);
    chmod_ops.chmod_err = Some(io::ErrorKind::PermissionDenied);
    let err =
        BoundSocket::bind_with_ops(&chmod_sock, SocketMode::OwnerOnly, &chmod_ops).unwrap_err();
    assert!(matches!(
        err,
        DaemonError::Io { ref source, .. } if source.kind() == io::ErrorKind::PermissionDenied
    ));
    assert_eq!(chmod_ops.chmod_calls.get(), 1);
    assert_eq!(
        fs::symlink_metadata(&chmod_sock).unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "RAII guard must unlink socket when post-bind set_permissions fails"
    );

    // 3. Post-chmod inode swap must be refused with PathExistsNotSocket.
    let swap_sock = canonical.join("swap.sock");
    let swap_ops = MockBindOps::new(host_euid);
    swap_ops
        .post_bind_results
        .borrow_mut()
        .push(Ok(PostBindMeta {
            is_symlink: false,
            is_socket: true,
            dev: 1,
            ino: 100,
        }));
    swap_ops
        .post_bind_results
        .borrow_mut()
        .push(Ok(PostBindMeta {
            is_symlink: false,
            is_socket: true,
            dev: 1,
            ino: 101,
        }));
    let err = BoundSocket::bind_with_ops(&swap_sock, SocketMode::OwnerOnly, &swap_ops).unwrap_err();
    assert!(matches!(err, DaemonError::PathExistsNotSocket(ref p) if p == &swap_sock));
}

#[test]
fn resolve_euid_handles_non_utf8_proc_status_and_fails_closed_on_errors_and_id_fallback() {
    // 1. Non-UTF-8 Name: line in /proc/self/status must parse Uid: cleanly without calling fallback.
    let raw_status = b"Name:\tbad\xff\xfename\nUid:\t1000\t1000\t1000\t1000\n";
    let euid = resolve_euid_with(
        || Ok(raw_status.to_vec()),
        || panic!("trusted id fallback must not be called when /proc/self/status succeeds"),
    )
    .expect("raw bytes /proc/self/status with non-UTF-8 Name must parse");
    assert_eq!(euid, 1000);

    // 2. Non-NotFound error (PermissionDenied) on /proc/self/status fails closed without fallback.
    let err = resolve_euid_with(
        || Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied")),
        || panic!("trusted id fallback must not be called on PermissionDenied"),
    )
    .unwrap_err();
    assert!(matches!(
        err,
        DaemonError::Io {
            path: Some(ref p),
            ref source,
        } if p == Path::new("/proc/self/status")
            && source.kind() == io::ErrorKind::PermissionDenied
    ));

    // 3. NotFound on /proc/self/status with trusted id exiting non-zero while printing "1000\n"
    // must fail closed inside BoundSocket::bind_with_ops BEFORE creating any socket on disk.
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    let sock = canonical.join("no_create_on_id_fail.sock");
    let mut ops = MockBindOps::new(1000);
    ops.euid_hook = Some(Box::new(|| {
        resolve_euid_with(
            || Err(io::Error::new(io::ErrorKind::NotFound, "no procfs")),
            || {
                Ok(Output {
                    status: ExitStatus::from_raw(1 << 8),
                    stdout: b"1000\n".to_vec(),
                    stderr: Vec::new(),
                })
            },
        )
    }));
    let err = BoundSocket::bind_with_ops(&sock, SocketMode::OwnerOnly, &ops).unwrap_err();
    assert!(matches!(err, DaemonError::Io { path: None, .. }));
    assert_eq!(
        fs::symlink_metadata(&sock).unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "socket must not be created when trusted id fallback exits non-zero"
    );

    // 4. run_trusted_id_at tries /bin/id ONLY when /usr/bin/id returns NotFound, and fails closed
    // immediately on PermissionDenied without searching further paths.
    let mut tried = Vec::new();
    let out = run_trusted_id_at(&TRUSTED_ID_PATHS, |path| {
        tried.push(path.to_string());
        if path == "/usr/bin/id" {
            Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
        } else {
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"1000\n".to_vec(),
                stderr: Vec::new(),
            })
        }
    })
    .unwrap();
    assert_eq!(tried, vec!["/usr/bin/id", "/bin/id"]);
    assert_eq!(parse_id_u_output(&out.stdout), Some(1000));

    let mut denied_tried = Vec::new();
    let denied = run_trusted_id_at(&TRUSTED_ID_PATHS, |path| {
        denied_tried.push(path.to_string());
        Err(io::Error::new(io::ErrorKind::PermissionDenied, "denied"))
    })
    .unwrap_err();
    assert_eq!(denied.kind(), io::ErrorKind::PermissionDenied);
    assert_eq!(denied_tried, vec!["/usr/bin/id"]);
}

#[test]
fn bind_resolves_relative_socket_path_once_and_drops_resolved_absolute_path() {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    let host_euid = current_euid().unwrap();

    let mut ops = MockBindOps::new(host_euid);
    ops.cwd = Some(canonical.clone());

    let expected_abs = canonical.join("approver.sock");
    let bound = BoundSocket::bind_with_ops(Path::new("approver.sock"), SocketMode::OwnerOnly, &ops)
        .expect("relative socket path must resolve against ops.current_dir()");
    assert!(bound.path().is_absolute());
    assert_eq!(bound.path(), expected_abs.as_path());
    assert!(fs::symlink_metadata(&expected_abs)
        .unwrap()
        .file_type()
        .is_socket());

    drop(bound);
    assert_eq!(
        fs::symlink_metadata(&expected_abs).unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "dropping BoundSocket must unlink the resolved absolute socket path"
    );
}

#[test]
fn bind_cleans_up_socket_on_first_post_bind_metadata_error_but_preserves_foreign_file() {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    let host_euid = current_euid().unwrap();

    // 1. Injected EIO on first post_bind_metadata must return Io AND remove our freshly bound socket.
    let eio_sock = canonical.join("post_bind_eio.sock");
    let eio_ops = MockBindOps::new(host_euid);
    eio_ops
        .post_bind_results
        .borrow_mut()
        .push(Err(DaemonError::Io {
            path: Some(eio_sock.clone()),
            source: io::Error::other("injected EIO"),
        }));
    let err = BoundSocket::bind_with_ops(&eio_sock, SocketMode::OwnerOnly, &eio_ops).unwrap_err();
    assert!(matches!(err, DaemonError::Io { .. }));
    assert_eq!(
        fs::symlink_metadata(&eio_sock).unwrap_err().kind(),
        io::ErrorKind::NotFound,
        "freshly bound socket must be removed on post_bind_metadata EIO"
    );

    // 2. If a foreign regular file occupies the path when post_bind_metadata fails, preserve it.
    let foreign_sock = canonical.join("post_bind_foreign.sock");
    let foreign_ops = MockBindOps::new(host_euid);
    *foreign_ops.post_bind_hook.borrow_mut() = Some(Box::new(|path: &Path| {
        fs::remove_file(path).unwrap();
        fs::write(path, b"foreign-keep").unwrap();
        Err(DaemonError::Io {
            path: Some(path.to_path_buf()),
            source: io::Error::other("injected EIO after swap"),
        })
    }));
    let err =
        BoundSocket::bind_with_ops(&foreign_sock, SocketMode::OwnerOnly, &foreign_ops).unwrap_err();
    assert!(matches!(err, DaemonError::Io { .. }));
    assert_eq!(
        fs::read(&foreign_sock).unwrap(),
        b"foreign-keep",
        "foreign regular file must be preserved on post_bind_metadata error cleanup"
    );
}

#[test]
fn bind_post_chmod_detects_device_change_and_preserves_real_replacement_entries() {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    let host_euid = current_euid().unwrap();

    // 1. Post-chmod recheck returning same ino on a DIFFERENT dev must be refused.
    let dev_sock = canonical.join("dev_swap.sock");
    let dev_ops = MockBindOps::new(host_euid);
    dev_ops
        .post_bind_results
        .borrow_mut()
        .push(Ok(PostBindMeta {
            is_symlink: false,
            is_socket: true,
            dev: 1,
            ino: 100,
        }));
    dev_ops
        .post_bind_results
        .borrow_mut()
        .push(Ok(PostBindMeta {
            is_symlink: false,
            is_socket: true,
            dev: 2,
            ino: 100,
        }));
    let err = BoundSocket::bind_with_ops(&dev_sock, SocketMode::OwnerOnly, &dev_ops).unwrap_err();
    assert!(matches!(err, DaemonError::PathExistsNotSocket(ref p) if p == &dev_sock));

    // 2. Real replacement during chmod with a regular file: bind refuses AND Drop preserves file.
    let file_rep_sock = canonical.join("replace_with_file.sock");
    let file_rep_ops = MockBindOps::new(host_euid);
    *file_rep_ops.chmod_hook.borrow_mut() = Some(Box::new(|path: &Path, _mode: u32| {
        fs::remove_file(path).unwrap();
        fs::write(path, b"replacement-regular-file").unwrap();
        Ok(())
    }));
    let err = BoundSocket::bind_with_ops(&file_rep_sock, SocketMode::OwnerOnly, &file_rep_ops)
        .unwrap_err();
    assert!(matches!(err, DaemonError::PathExistsNotSocket(ref p) if p == &file_rep_sock));
    assert_eq!(
        fs::read(&file_rep_sock).unwrap(),
        b"replacement-regular-file",
        "Drop must preserve replacement regular file created during chmod"
    );

    // 3. Real replacement during chmod with a second Unix socket (new inode): bind refuses AND
    // Drop preserves the replacement socket because its (dev, ino) differs from bound's.
    let sock_rep_path = canonical.join("replace_with_sock.sock");
    let sock_rep_ops = MockBindOps::new(host_euid);
    let replacement_listener: std::rc::Rc<std::cell::RefCell<Option<UnixListener>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let holder = std::rc::Rc::clone(&replacement_listener);
    *sock_rep_ops.chmod_hook.borrow_mut() = Some(Box::new(move |path: &Path, _mode: u32| {
        fs::remove_file(path).unwrap();
        let replacement = UnixListener::bind(path).unwrap();
        *holder.borrow_mut() = Some(replacement);
        Ok(())
    }));
    let err = BoundSocket::bind_with_ops(&sock_rep_path, SocketMode::OwnerOnly, &sock_rep_ops)
        .unwrap_err();
    assert!(matches!(err, DaemonError::PathExistsNotSocket(ref p) if p == &sock_rep_path));
    assert!(fs::symlink_metadata(&sock_rep_path)
        .expect("replacement socket must still exist after refusal and Drop")
        .file_type()
        .is_socket());
}

#[test]
fn untrusted_ancestor_diagnostic_is_accurate_for_root_parent_and_non_root_daemon() {
    let root = tempfile::TempDir::new().unwrap();
    let canonical_root = fs::canonicalize(root.path()).unwrap();
    fs::set_permissions(&canonical_root, fs::Permissions::from_mode(0o700)).unwrap();
    let ancestor = canonical_root.join("mallory_ancestor");
    let parent = ancestor.join("root_parent");
    fs::create_dir(&ancestor).unwrap();
    fs::set_permissions(&ancestor, fs::Permissions::from_mode(0o755)).unwrap();
    fs::create_dir(&parent).unwrap();
    fs::set_permissions(&parent, fs::Permissions::from_mode(0o700)).unwrap();
    let sock = parent.join("approver.sock");

    let mut ops = MockBindOps::new(1000);
    ops.dir_overrides.push((
        ancestor.clone(),
        DirPrefixInfo {
            mode: 0o755,
            uid: 2000,
        },
    ));
    ops.dir_overrides.push((
        parent,
        DirPrefixInfo {
            mode: 0o700,
            uid: 0,
        },
    ));

    let err = BoundSocket::bind_with_ops(&sock, SocketMode::OwnerOnly, &ops).unwrap_err();
    assert!(matches!(
        err,
        DaemonError::UntrustedAncestorOwner {
            ref path,
            ancestor_uid: 2000,
            expected_uid: 1000,
        } if path == &ancestor
    ));
    let msg = err.to_string();
    assert!(msg.contains("owned by uid 2000"), "unexpected msg: {msg}");
    assert!(
        msg.contains("expected root or daemon euid 1000"),
        "unexpected msg: {msg}"
    );
    assert!(
        !msg.contains("parent owner uid"),
        "diagnostic must not misreport daemon euid as parent owner uid: {msg}"
    );
}

#[test]
fn bind_preserves_live_replacement_listener_on_first_post_bind_metadata_error() {
    let dir = tempfile::TempDir::new().unwrap();
    let canonical = fs::canonicalize(dir.path()).unwrap();
    fs::set_permissions(&canonical, fs::Permissions::from_mode(0o700)).unwrap();
    let host_euid = current_euid().unwrap();

    let live_sock = canonical.join("post_bind_live_replacement.sock");
    let ops = MockBindOps::new(host_euid);
    let replacement_holder: std::rc::Rc<std::cell::RefCell<Option<(UnixListener, u64, u64)>>> =
        std::rc::Rc::new(std::cell::RefCell::new(None));
    let holder_ref = std::rc::Rc::clone(&replacement_holder);
    *ops.post_bind_hook.borrow_mut() = Some(Box::new(move |path: &Path| {
        fs::remove_file(path).unwrap();
        let replacement = UnixListener::bind(path).unwrap();
        let meta = fs::symlink_metadata(path).unwrap();
        *holder_ref.borrow_mut() = Some((replacement, meta.dev(), meta.ino()));
        Err(DaemonError::Io {
            path: Some(path.to_path_buf()),
            source: io::Error::other("injected EIO after live listener replacement"),
        })
    }));

    let err = BoundSocket::bind_with_ops(&live_sock, SocketMode::OwnerOnly, &ops).unwrap_err();
    assert!(matches!(err, DaemonError::Io { .. }));

    let holder = replacement_holder.borrow();
    let (_, expected_dev, expected_ino) = holder
        .as_ref()
        .expect("post_bind_hook must have bound replacement listener");
    let after_meta = fs::symlink_metadata(&live_sock)
        .expect("live replacement listener socket must still exist after post-bind cleanup");
    assert!(after_meta.file_type().is_socket());
    assert_eq!(after_meta.dev(), *expected_dev);
    assert_eq!(after_meta.ino(), *expected_ino);
    UnixStream::connect(&live_sock)
        .expect("live replacement listener must remain connectable after post-bind cleanup");
}

#[test]
fn resolve_euid_covers_malformed_proc_and_id_fallback_outcomes() {
    // 1. Readable malformed /proc/self/status fails closed with InvalidData without calling fallback.
    for malformed in [
        b"Name:\thandfest\n".as_slice(),
        b"Uid:\t1000\tnotnum\n".as_slice(),
    ] {
        let err = resolve_euid_with(
            || Ok(malformed.to_vec()),
            || panic!("fallback must not run when /proc/self/status is readable but malformed"),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DaemonError::Io {
                path: Some(ref p),
                ref source,
            } if p == Path::new("/proc/self/status")
                && source.kind() == io::ErrorKind::InvalidData
        ));
    }

    // 2. Launcher I/O errors on NotFound fallback fail closed with matching ErrorKind.
    for kind in [io::ErrorKind::NotFound, io::ErrorKind::PermissionDenied] {
        let err = resolve_euid_with(
            || Err(io::Error::new(io::ErrorKind::NotFound, "no procfs")),
            || Err(io::Error::new(kind, "launcher failure")),
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DaemonError::Io {
                path: None,
                ref source,
            } if source.kind() == kind
        ));
    }

    // 3. Valid successful output on fallback returns the parsed EUID.
    let ok_euid = resolve_euid_with(
        || Err(io::Error::new(io::ErrorKind::NotFound, "no procfs")),
        || {
            Ok(Output {
                status: ExitStatus::from_raw(0),
                stdout: b"4242\n".to_vec(),
                stderr: Vec::new(),
            })
        },
    )
    .expect("valid trusted id output must succeed");
    assert_eq!(ok_euid, 4242);

    // 4. Malformed successful output on fallback fails closed with InvalidData.
    for bad_stdout in [
        b"".as_slice(),
        b"not-a-uid\n".as_slice(),
        b"\xff\xfe".as_slice(),
    ] {
        let err = resolve_euid_with(
            || Err(io::Error::new(io::ErrorKind::NotFound, "no procfs")),
            || {
                Ok(Output {
                    status: ExitStatus::from_raw(0),
                    stdout: bad_stdout.to_vec(),
                    stderr: Vec::new(),
                })
            },
        )
        .unwrap_err();
        assert!(matches!(
            err,
            DaemonError::Io {
                path: None,
                ref source,
            } if source.kind() == io::ErrorKind::InvalidData
        ));
    }

    // 5. All trusted paths missing (or empty list) returns NotFound.
    let all_missing = run_trusted_id_at(&TRUSTED_ID_PATHS, |_| {
        Err(io::Error::new(io::ErrorKind::NotFound, "missing"))
    })
    .unwrap_err();
    assert_eq!(all_missing.kind(), io::ErrorKind::NotFound);
    let empty_paths = run_trusted_id_at(&[], |_| panic!("must not exec empty list")).unwrap_err();
    assert_eq!(empty_paths.kind(), io::ErrorKind::NotFound);
}

#[test]
fn run_trusted_id_command_clears_env_and_passes_dash_u() {
    // Production command builder passes `-u` and clears inherited environment variables,
    // working cleanly even under `env -i`, non-UTF-8 ambient values, or digit-prefixed keys.
    let dir = tempfile::TempDir::new().unwrap();
    let missing_bin = dir.path().join("no_such_id");
    let fake_id = dir.path().join("fake_id");
    let script = "#!/bin/sh\nif [ \"$#\" -ne 1 ] || [ \"$1\" != \"-u\" ]; then exit 2; fi\nfor line in $(env); do\n  case \"$line\" in\n    PWD=*|SHLVL=*|_\\=*) ;;\n    *) exit 3 ;;\n  esac\ndone\nprintf '31337\\n'\n";
    fs::write(&fake_id, script).unwrap();
    fs::set_permissions(&fake_id, fs::Permissions::from_mode(0o700)).unwrap();

    let paths = [missing_bin.to_str().unwrap(), fake_id.to_str().unwrap()];
    let out = run_trusted_id_from_paths(&paths)
        .expect("production command runner must fall through NotFound and execute fake_id");
    assert!(
        out.status.success(),
        "production command must pass `-u` and clear inherited env, got status {}",
        out.status
    );
    assert_eq!(parse_id_u_output(&out.stdout), Some(31337));

    // Also verify real `run_trusted_id()` agrees with host `current_euid()`.
    let real_out = run_trusted_id().expect("host trusted id executable must succeed");
    assert!(real_out.status.success());
    assert_eq!(
        parse_id_u_output(&real_out.stdout),
        Some(current_euid().unwrap())
    );
}

#[test]
fn bind_rejects_resolved_relative_path_with_invalid_utf8_or_control_chars() {
    use std::ffi::OsString;
    use std::os::unix::ffi::OsStringExt;

    // 1. Clean relative input expanded under non-UTF-8 cwd must be rejected before euid/bind.
    let mut non_utf8_ops = MockBindOps::new(1000);
    non_utf8_ops.cwd = Some(PathBuf::from(OsString::from_vec(
        b"/tmp/bad\xffdir".to_vec(),
    )));
    non_utf8_ops.euid_hook = Some(Box::new(|| {
        panic!("current_euid must not run after invalid resolved path")
    }));
    let err = BoundSocket::bind_with_ops(
        Path::new("approver.sock"),
        SocketMode::OwnerOnly,
        &non_utf8_ops,
    )
    .unwrap_err();
    assert!(
        matches!(err, DaemonError::InvalidConfig(ref msg) if msg.contains("UTF-8")),
        "expected InvalidConfig UTF-8 error, got {err:?}"
    );

    // 2. Clean relative input expanded under cwd containing control characters must be rejected.
    for bad_cwd in ["/tmp/bad\x1b[31mdir", "/tmp/bad\ndir"] {
        let mut ctrl_ops = MockBindOps::new(1000);
        ctrl_ops.cwd = Some(PathBuf::from(bad_cwd));
        ctrl_ops.euid_hook = Some(Box::new(|| {
            panic!("current_euid must not run after control-char resolved path")
        }));
        let err = BoundSocket::bind_with_ops(
            Path::new("approver.sock"),
            SocketMode::OwnerOnly,
            &ctrl_ops,
        )
        .unwrap_err();
        assert!(
            matches!(err, DaemonError::InvalidConfig(ref msg) if msg.contains("control")),
            "expected InvalidConfig control-char error for {bad_cwd:?}, got {err:?}"
        );
    }
}

#[test]
fn near_max_instant_reaches_upper_bound_from_low_uptime_instants() {
    let now = Instant::now();
    let mut floor = now;
    let mut step = 1u64 << 63;
    while step > 0 {
        if let Some(prev) = floor.checked_sub(Duration::from_secs(step)) {
            floor = prev;
        }
        step >>= 1;
    }

    let mut starts = vec![floor, now];
    for offset in [1u64, 5, 39, 62, 63] {
        if let Some(t) = floor.checked_add(Duration::from_secs(offset)) {
            starts.push(t);
        }
    }
    // On signed 64-bit `timespec` platforms (`i64::MIN..=i64::MAX`), `floor + 2^63` lands at
    // `tv_sec == 0`, modeling a fresh time namespace whose monotonic clock started seconds ago.
    if let Some(zero_epoch) = floor.checked_add(Duration::from_secs(1u64 << 63)) {
        for offset in [0u64, 1, 5, 39, 62, 63] {
            if let Some(t) = zero_epoch.checked_add(Duration::from_secs(offset)) {
                starts.push(t);
            }
        }
    }

    for start in starts {
        let upper = near_max_instant_from(start);
        assert!(upper >= start);
        assert!(upper.checked_add(Duration::from_secs(1)).is_none());
        // Already at the upper bound is idempotent.
        let again = near_max_instant_from(upper);
        assert_eq!(again, upper);
    }
}

#[test]
fn bind_rejects_trailing_slash_dot_parent_components_root_and_bad_cwd() {
    let dir = tempfile::TempDir::new().unwrap();
    fs::set_permissions(dir.path(), fs::Permissions::from_mode(0o700)).unwrap();

    // Production RealSocketBindOps::current_dir matches std::env::current_dir().
    assert_eq!(
        RealSocketBindOps.current_dir().unwrap(),
        std::env::current_dir().unwrap()
    );

    // Trailing slash, `.`, `..`, and root `/` are rejected before filesystem touch.
    for bad in [
        dir.path().join("link.sock/"),
        dir.path().join("link.sock/."),
        PathBuf::from("."),
        PathBuf::from("../approver.sock"),
        PathBuf::from("/"),
    ] {
        let err = BoundSocket::bind(&bad, SocketMode::OwnerOnly).unwrap_err();
        assert!(
            matches!(err, DaemonError::InvalidConfig(_)),
            "expected InvalidConfig for {bad:?}, got {err:?}"
        );
    }

    // Relative cwd from ops seam is rejected.
    let euid = current_euid().unwrap();
    let mut rel_cwd_ops = MockBindOps::new(euid);
    rel_cwd_ops.cwd = Some(PathBuf::from("relative/dir"));
    let rel_err = BoundSocket::bind_with_ops(
        Path::new("approver.sock"),
        SocketMode::OwnerOnly,
        &rel_cwd_ops,
    )
    .unwrap_err();
    assert!(matches!(rel_err, DaemonError::InvalidConfig(_)));

    // Post-chmod metadata I/O error triggers BoundSocket::drop cleanup.
    let sock = dir.path().join("post-chmod-err.sock");
    let call_count = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let call_count_clone = std::sync::Arc::clone(&call_count);
    let mut post_chmod_ops = MockBindOps::new(euid);
    post_chmod_ops.post_bind_hook = std::cell::RefCell::new(Some(Box::new(move |path| {
        if call_count_clone.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
            RealSocketBindOps.post_bind_metadata(path)
        } else {
            Err(DaemonError::Io {
                path: Some(path.to_path_buf()),
                source: io::Error::other("injected post-chmod metadata failure"),
            })
        }
    })));
    let err =
        BoundSocket::bind_with_ops(&sock, SocketMode::OwnerOnly, &post_chmod_ops).unwrap_err();
    assert!(matches!(err, DaemonError::Io { .. }));
    assert!(
        !sock.exists(),
        "post-chmod metadata error must clean up bound socket via Drop"
    );
}
