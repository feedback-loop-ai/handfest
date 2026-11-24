# starter — scaffolded by `brokkr init`

This directory was scaffolded from inside a repository that reads
as a rust project (`Cargo.toml`). Everything here is ordinary text:
read it, edit it, commit it.

## What is here

- `bundle.json` — three model offices plus the verify and ship exec
  gates, which `namespace` boxes,
with each seat's results and limits.
- `policy.json` — the phase table; `review` is the protected phase.
- `adapters/claude.json` and `adapters/exec.json` — the model and
deterministic drivers, including their trust tiers.
- `agents/*.json` — one agent per model office: charter, model chain,
tool allowance, limits. `brokkr agents show <name>` reads one back.
- `agents/charters/*.md` — the three model-office charters.
- `scripts/*.sh` — deterministic verify and ship offices; verify
names this repository's own commands and runs in Brokkr's box, without network.

## Tool grants

`adapters/claude.json` maps each tool the seats are granted below
to the `Bash(...)` expression the claude CLI reads — the stack's
own runners, and nothing broader:

    cargo → Bash(cargo:*)
    git → Bash(git:*)
    ls → Bash(ls:*)
    rg → Bash(rg:*)
    mkdir → Bash(mkdir:*)

Work-class seats (intake, implement) are pre-approved for the whole set:
cargo, git, ls, rg, mkdir. Pre-approval removes no tool: an unboxed seat keeps the
harness's other defaults and your own permission settings. Only
`WebSearch` and `WebFetch` are denied, by name, because
`realms.json` grants neither.

The model-backed review gate is pre-approved for a smaller set — the
test runner's tools and the tools that read — and never `mkdir`:
cargo, git, ls, rg. Verify and ship are exec scripts with no model grant,
and `namespace` boxes them.

The grant is per BINARY, not per subcommand: the test runner's
binary also answers to its build and install subcommands, so it is
each gate's charter (prove it, fix nothing) and not the grant that
keeps a gate from building. The review gate also runs unboxed under `acceptEdits`, as every
claude seat here does, so it can edit files: the engine parks a gate
that moves HEAD, and an edit it leaves uncommitted moves nothing.

An allowance is ONE grant with the adapter's `tool_permissions.names`:
an allowance whose name the map cannot express refuses this
scaffold's own compile, so when you edit one, edit both.

`brokkr init` chose all of this from the files at the repository
root — it ran nothing to find out. Correct it here if it is wrong.

## Agent CLI and boundary

Scaffolded for `claude`, the first of claude, codex and dsh found on PATH.

Decision 0065 rules that a seat never inherits your own MCP configuration, but this build does not enforce it yet: a seat may still start the MCP servers your harness configuration names.

## Specification dialect

Found neither `.specify/` (spec-kit) nor `openspec/config.yaml` (OpenSpec), so `realms.json` carries no dialect. An artifact phase will need one before it can run.
