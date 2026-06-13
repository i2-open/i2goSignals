# Issue tracker: GitHub

Issues and PRDs for this repo live as GitHub issues in `i2-open/i2goSignals`.

**Use the `gh` CLI** for all operations — it works again on the maintainer's machine as
of 2026-06-12 (the earlier Rosetta limitation is resolved), and it is what headless /
container environments (e.g. the Sandcastle agent, see `.sandcastle/`) have installed.
The GitHub MCP server (`mcp__github__*` tools) remains a fallback for sessions where
`gh` is unavailable.

## Conventions

| Operation | `gh` CLI (preferred) | MCP fallback |
|-----------|----------------------|--------------|
| **Create an issue** | `gh issue create --title "..." --body "..."` (heredoc for multi-line bodies) | `mcp__github__create_issue` (`owner`, `repo`, `title`, `body`) |
| **Read an issue** | `gh issue view <number> --comments` (filter comments by `jq`, also fetch labels) | `mcp__github__get_issue` + `mcp__github__get_issue_comments` |
| **List issues** | `gh issue list --state open --json number,title,body,labels,comments --jq '[.[] | {number, title, body, labels: [.labels[].name], comments: [.comments[].body]}]'` with `--label` / `--state` filters | `mcp__github__list_issues` (filter by `labels`, `state`) |
| **Comment on an issue** | `gh issue comment <number> --body "..."` | `mcp__github__add_issue_comment` |
| **Apply / remove labels** | `gh issue edit <number> --add-label "..."` / `--remove-label "..."` | `mcp__github__update_issue` (`labels`) |
| **Close** | `gh issue close <number> --comment "..."` | `mcp__github__update_issue` (`state: closed`), then `add_issue_comment` for the note |

Owner/repo are `i2-open` / `i2goSignals`. With the `gh` CLI, the repo is inferred from
`git remote -v` automatically when run inside a clone; MCP tools need `owner` and `repo`
passed explicitly.

> **Note:** label *creation* (`gh label create`) has no GitHub MCP equivalent — it is
> `gh`-only regardless of environment.

## When a skill says "publish to the issue tracker"

Create a GitHub issue (`gh issue create`).

## When a skill says "fetch the relevant ticket"

Read the issue (`gh issue view <number> --comments`).
