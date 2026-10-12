# Issue tracker: GitHub

Issues and specs live in GitHub Issues for `dnsgateway/dnsprovider`.
Use the `gh` CLI, which infers the repository from the git remote.

## Conventions

- Create: `gh issue create --title "..." --body-file <file>`
- Read: `gh issue view <number> --comments`
- List: `gh issue list --state open --json number,title,body,labels`
- Comment: `gh issue comment <number> --body-file <file>`
- Apply labels: `gh issue edit <number> --add-label "..."`
- Remove labels: `gh issue edit <number> --remove-label "..."`
- Close: `gh issue close <number> --comment "..."`

For multiline bodies, write the text to a temporary file and use
`--body-file`.

## Pull requests as a triage surface

**PRs as a request surface: no.**

## Publishing and fetching tickets

When a skill says "publish to the issue tracker", create a GitHub issue.
When a skill says "fetch the relevant ticket", read the issue with comments.

## Wayfinding operations

- Map: one issue labelled `wayfinder:map`, containing Notes,
  Decisions-so-far, and Fog.
- Child tickets: link issues as GitHub sub-issues. If unavailable,
  use a task list in the map and `Part of #<map>` in each child.
  Use `wayfinder:research`, `wayfinder:prototype`, `wayfinder:grilling`,
  or `wayfinder:task` labels.
- Blocking: use native GitHub issue dependencies. If unavailable,
  record `Blocked by: #<number>` in the child. A ticket is unblocked
  when every blocker is closed.
- Frontier: choose the first open child in map order that has no
  open blockers and no assignee.
- Claim: `gh issue edit <number> --add-assignee @me`.
- Resolve: comment with the result, close the ticket, and append a
  context pointer to the map's Decisions-so-far.
