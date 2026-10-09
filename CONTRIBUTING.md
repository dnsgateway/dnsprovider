# Contributing

## Pull Requests

### Creating Pull Requests

Use `.github/PULL_REQUEST_TEMPLATE.md` as the structure for every PR description.

Every PR must include:

- **What?** — a clear description of the changes made.
- **Why?** — the reasoning or motivation, linking the related issue when applicable.
- **Acceptance checklist** — complete the checklist items truthfully:
  - [ ] linked an issue (if applicable)
  - [ ] included tests (if applicable)
  - [ ] ran conformance (`make conformance`)
  - [ ] linted code (`make lint`)
  - [ ] ran unit tests (`make unit`)
  - [ ] disclosed AI usage honestly

### Maintaining Pull Requests

- Address review feedback by force-pushing to the PR branch.
- Update the PR description when the scope of the change evolves so it always reflects the current diff.
- Rebase onto the target branch when requested to resolve conflicts; squash commits into a single commit.
- Ensure CI is green before requesting re-review.

All PRs require a single commit.

Having one commit in a Pull Request is very important for several reasons:
* A single commit per PR keeps the git history clean and readable.
  It helps reviewers and future developers understand the change as one atomic unit of work,
  instead of sifting through many intermediate or redundant commits.
* One commit is easier to cherry-pick into another branch or to track in changelogs.
* Squashing into one meaningful commit ensures the final PR only contains what matters.

### Commit Messages and PR Titles

Use [Conventional Commits 1.0.0](https://www.conventionalcommits.org/en/v1.0.0/)
for commit messages and PR titles:

```text
<type>[optional scope][!]: <description>
```

Keep the entire header lowercase, including the type, scope, and description.
This lowercase requirement is a repository convention. Use `feat` for new
features, `fix` for bug fixes, and an appropriate type such as `docs`, `test`,
or `refactor` for other changes. Use a scope to identify the affected area
when helpful, and keep the PR title aligned with its single commit's header.

For example:

```text
feat(provider-name): add the cloudns provider
```

Put an optional body and footers after a blank line. Mark breaking changes
with `!` before the colon or an uppercase `BREAKING CHANGE:` footer. Preserve
the DCO `Signed-off-by:` footer; the lowercase rule applies only to the header.

## GitHub Issues

### Creating Issues

- Use the templates in `.github/ISSUE_TEMPLATE/` when creating issues:
  - `BUG_REPORT.md` — for reporting bugs.
  - `FEATURE_REQUEST.md` — for proposing new features or enhancements.
- Every issue must have:
  - A clear, descriptive **title**.
  - A concise **description** of the problem or request.
  - **Steps to reproduce** for bugs.
- Fill in the body, do not remove the "Community Note" section.
- Link related issues or PRs in the description when applicable.

### Maintaining Issues

- Keep issue descriptions up to date as new information is gathered (reproduction steps, environment details, error logs).
- Add follow-up comments with new findings, test results, or workarounds instead of editing over important history.
- Close issues once resolved, and reference the PR or commit that fixed them.
- Reopen issues only if the fix is reverted or proven incomplete.

## Developer Certificate of Origin

All commits require a [DCO](https://developercertificate.org/) sign-off.
This is done by committing with the `--signoff` flag.

## Development

Install Git, make, and Go matching `go.mod` (currently Go 1.24.0). CI reads
its Go version from that file. Install golangci-lint v2.13.2, the version
used by CI, for the configured lint checks. Docker is needed for conformance;
normal builds and tests run locally and do not require containers. The Go
requirement printed by `make help` may differ; follow `go.mod`.

Clone the repository and download dependencies:

```sh
git clone https://github.com/dnsgateway/dnsprovider.git
cd dnsprovider
go mod download
make help
```

Validate changes with:

```sh
make unit                 # all Go tests
make vet                  # go vet ./...
make lint                 # .golangci.yml, including tests
go test -race ./...       # race checks
make conformance          # commit policy and DCO; requires Docker
```

Report unavailable tooling and failed checks accurately in the PR checklist.
Run `gofmt` on changed Go files. `make test` combines lint and unit tests.
`make tools` installs the optional license checker; `make licenses` runs it.

### Deterministic and live tests

Default tests use local HTTP fixtures and require no real provider account.
Keep `DNSPROVIDER_*` credentials unset for deterministic test and lint runs:
live tests share the normal test suite and activate when their required secret
fields are configured. Live checks only read Account, Zones, and Records; they
must never mutate real DNS. Each adapter's documentation in `docs/provider/`
lists its environment variables and optional endpoint override.

To run Internet.bs read-only checks explicitly, configure
`DNSPROVIDER_INTERNETBS_KEY` and `DNSPROVIDER_INTERNETBS_PASSWORD`, then run
`go test ./providers/internetbs -run '^TestLive$' -v`. The optional
`DNSPROVIDER_INTERNETBS_BASE_URL` selects another endpoint. Public sandbox
credentials must never be enabled implicitly.

### Adding or changing a provider

Start from the associated GitHub issue and verify the protocol against official
provider documentation. Read relevant domain vocabulary and decisions in
`GLOSSARY.md` and `docs/adr/` when present. Keep the root Provider interface
stable and use shared Options, validation, filters, error types, and Apply.

An adapter in `providers/<name>` exports typed `Config`, `New`, and `Factory`.
Construction validates locally without network calls. Mark secret Factory
fields, reject unknown fields, and declare only implemented optional
capabilities. Honor custom HTTP clients, endpoint overrides, and logging;
prevent credentials from reaching diagnostics. Discover complete inventories,
normalize names, preserve unrelated Records, and make uncertain write outcomes
and retry behavior explicit.

Test consumer-visible behavior through the exported Provider and Apply using
protocol-faithful local `httptest` fixtures in the external test package.
Cover configuration, filtering, errors, write selection, preservation of
siblings, and partial failures. Register the adapter in `providers.Registry`
while retaining existing entries and independent Registry maps, and update
Registry contract tests. Add an optional read-only live test using
`internal/livetest`, a setup/limitations page in `docs/provider/`, and entries
in README.md and `docs/provider.md`. Add the provider scope to `.conform.yaml`.

Before submitting, run the validation commands above, preserve the PR template,
squash the final PR to one lowercase Conventional Commit, and include its
`Signed-off-by:` footer. Disclose AI usage honestly.
