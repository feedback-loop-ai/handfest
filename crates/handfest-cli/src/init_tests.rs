use super::*;

#[test]
fn resolve_init_dir_precedence_and_empty_rejection() {
    assert_eq!(
        resolve_init_dir_from(
            Some(PathBuf::from("/custom")),
            Some(OsString::from("/env")),
            Some(OsString::from("/home/u")),
        )
        .unwrap(),
        PathBuf::from("/custom")
    );
    assert_eq!(
        resolve_init_dir_from(
            None,
            Some(OsString::from("/env")),
            Some(OsString::from("/home/u")),
        )
        .unwrap(),
        PathBuf::from("/env")
    );
    assert_eq!(
        resolve_init_dir_from(None, Some(OsString::new()), Some(OsString::from("/home/u")))
            .unwrap(),
        PathBuf::from("/home/u/.handfest")
    );
    assert!(
        resolve_init_dir_from(Some(PathBuf::new()), None, Some(OsString::from("/home/u")))
            .unwrap_err()
            .contains("--dir must not be empty")
    );
    assert!(resolve_init_dir_from(None, None, None)
        .unwrap_err()
        .contains("cannot determine default handfest directory"));
}

#[test]
fn profile_schema_rejects_unknown_fields() {
    let raw = r#"{
        "schema": "handfest.profile/v1",
        "principal_name": "Valentin",
        "principal_key_id": "ed25519:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "signer_kind": "ssh-sk",
        "signer_hint": "/home/v/.ssh/id_ed25519_sk.pub",
        "agent_name": "agent",
        "agent_key_id": "ed25519:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        "mandates_dir": "/tmp/m",
        "ledger_path": "/tmp/l.sqlite",
        "policy_map_path": "/tmp/p.json",
        "secret_key_hex": "deadbeef"
    }"#;
    let err = serde_json::from_str::<HandfestProfile>(raw).unwrap_err();
    assert!(err.to_string().contains("unknown field"));
}

#[test]
fn reject_git_worktree_catches_git_dir_and_file() {
    let tmp = tempfile::TempDir::new().unwrap();
    let repo = tmp.path().join("repo");
    fs::create_dir_all(repo.join(".git")).unwrap();
    let nested = repo.join("sub/handfest");
    let err = reject_git_worktree(&nested).unwrap_err();
    assert!(err.contains("inside git working tree"));

    let worktree = tmp.path().join("wt");
    fs::create_dir_all(&worktree).unwrap();
    fs::write(worktree.join(".git"), "gitdir: /somewhere/else\n").unwrap();
    let err_wt = reject_git_worktree(&worktree.join("cfg")).unwrap_err();
    assert!(err_wt.contains("inside git working tree"));

    let safe = tmp.path().join("outside");
    reject_git_worktree(&safe).expect("non-git path must pass");
}

#[test]
fn shell_quote_handles_safe_and_special_strings() {
    assert_eq!(shell_quote("/home/user/.handfest"), "/home/user/.handfest");
    assert_eq!(shell_quote("/tmp/a b/c'd"), "'/tmp/a b/c'\"'\"'d'");
    assert_eq!(shell_quote(""), "''");
}

#[test]
fn init_rejects_corrupt_ledger_non_file_paths_and_invalid_names() {
    let tmp = tempfile::TempDir::new().unwrap();
    let human_kp = Ed25519Keypair::from_secret_bytes([0x41; 32]);
    let human_key_path = tmp.path().join("human.key.json");
    fs::write(
        &human_key_path,
        serde_json::to_string_pretty(&human_kp.to_key_file()).unwrap(),
    )
    .unwrap();

    // Corrupt existing ledger must fail closed and not be overwritten.
    let dir1 = tmp.path().join("cfg1");
    fs::create_dir_all(dir1.join("state")).unwrap();
    let bad_ledger = dir1.join("state/handfest-ledger.sqlite");
    fs::write(&bad_ledger, b"not-sqlite").unwrap();
    let err = init_profile_with_runner(
        &dir1,
        "Valentin",
        "agent",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(human_key_path.clone()),
        SystemCommandRunner,
    )
    .unwrap_err();
    assert!(err.contains("failed to verify existing ledger"));
    assert_eq!(fs::read(&bad_ledger).unwrap(), b"not-sqlite");

    // Directory at ledger path fails closed.
    let dir_led = tmp.path().join("cfg_dir_ledger");
    fs::create_dir_all(dir_led.join("state/handfest-ledger.sqlite")).unwrap();
    let err_led = init_profile_with_runner(
        &dir_led,
        "Valentin",
        "agent",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(human_key_path.clone()),
        SystemCommandRunner,
    )
    .unwrap_err();
    assert!(err_led.contains("not a regular file"));

    // Directory at agent.key.json fails closed.
    let dir2 = tmp.path().join("cfg2");
    fs::create_dir_all(dir2.join("agent.key.json")).unwrap();
    let err2 = init_profile_with_runner(
        &dir2,
        "Valentin",
        "agent",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(human_key_path.clone()),
        SystemCommandRunner,
    )
    .unwrap_err();
    assert!(err2.contains("not a regular file"));

    // Regular file at target --dir fails closed.
    let file_dir = tmp.path().join("not-a-dir");
    fs::write(&file_dir, "hello").unwrap();
    let err_dir = init_profile_with_runner(
        &file_dir,
        "Valentin",
        "agent",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(human_key_path.clone()),
        SystemCommandRunner,
    )
    .unwrap_err();
    assert!(err_dir.contains("not a directory"));

    // Invalid principal_name and agent_name fail closed before creating target dir.
    let dir3 = tmp.path().join("cfg3");
    assert!(init_profile_with_runner(
        &dir3,
        "",
        "agent",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(human_key_path.clone()),
        SystemCommandRunner,
    )
    .unwrap_err()
    .contains("invalid --principal-name"));
    assert!(!dir3.exists());

    assert!(init_profile_with_runner(
        &dir3,
        "Valentin",
        "",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(human_key_path),
        SystemCommandRunner,
    )
    .unwrap_err()
    .contains("invalid --agent-name"));
    assert!(!dir3.exists());

    assert!(init_profile_with_runner(
        &dir3,
        "Valentin\nBad",
        "agent",
        None,
        false,
        &PrincipalKeySource::LocalEd25519(tmp.path().join("human.key.json")),
        SystemCommandRunner,
    )
    .unwrap_err()
    .contains("invalid --principal-name"));
    assert!(!dir3.exists());
}
