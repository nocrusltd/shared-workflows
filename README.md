# shared-workflows

Reusable GitHub Actions workflows for Nocrus repositories. Public so that both
private and public repositories can call them: a public repository can only
call reusable workflows held in a public repository.

Nothing here uses or needs a secret.

## Secret scan (gitleaks)

`.github/workflows/gitleaks-reusable.yml` scans the commits a pull request or a
push introduces for secrets, using the open-source
[gitleaks](https://github.com/gitleaks/gitleaks) binary (MIT), pinned by version
and SHA-256. It never scans the full history.

What it does, in short:

- Scans only the new commits, commit by commit, and once more as the single
  net change the range makes to the base (this catches a secret that reaches a
  scanned path only through a merge).
- Uses gitleaks' default rules with the three file-type exclusions removed
  (images, fonts, documents and binaries), so a secret in such a file is not
  skipped. Lock files, `go.sum`, vendored directories and `node_modules` stay
  excluded on purpose.
- Reads exceptions only from `.gitleaksignore` as it is on the **base** (the
  pull request's base commit, or the previous tip for a push). A pull request
  cannot allow-list its own finding, and an inline `gitleaks:allow` comment or a
  `.gitleaks.toml` in the repository is ignored.
- Redacts secret values in the log and job summary. Nothing is uploaded.
- Fails closed if the commit range cannot be established.

### Calling it

Private repository:

```yaml
name: Secret scan (gitleaks)
on:
  pull_request_target:
    # 'edited' too: changing a pull request's base branch is an 'edited' event
    types: [opened, synchronize, reopened, edited]
  push:
    branches: [main]
permissions:
  contents: read
jobs:
  gitleaks:
    uses: nocrusltd/shared-workflows/.github/workflows/gitleaks-reusable.yml@<full commit SHA on main>
    with:
      runs-on: ubuntu-latest
```

`pull_request_target` runs the caller from the repository's default branch, so
a pull request cannot edit or remove the scanner that checks it. That trigger is
safe here only because the workflow executes nothing from the pull request,
uses no secrets and has a read-only token.

Public repository: use `pull_request` instead of `pull_request_target`. GitHub
blocks `pull_request_target` by default in public repositories from
2026-12-02 unless an Actions event policy allows it. Under `pull_request` a
fork's pull request gets a read-only token and no secrets; the trade-off is that
the pull request's own copy of the caller runs, so review changes to it.

Set `push.branches` to the repository's default branch.

### Pinning

Always reference the workflow at a **full commit SHA** on `main`, never a
branch or tag. To take a newer version, change the SHA in a reviewed pull
request.

The check name a calling repository sees is
`gitleaks / gitleaks (new commits only)`.

### When it finds something

Remove the secret from the branch history (amend or rebase, not a follow-up
commit) and rotate it. A proven false positive is allow-listed by its
fingerprint (`[commit:]file:rule:line`) in `.gitleaksignore`, merged in its own
change first, because the scan reads that file from the base.

Merging the exception does not re-run the pull request's scan, and re-running
the old run reuses the old base. Push a new commit to the pull request's branch
(an empty commit is enough; it keeps the finding's commit fingerprint) so a new
scan runs against the base that now holds the exception.

### Running it by hand

The workflow header gives the exact commands for both passes. Work in a
disposable clone and delete its working-tree `.gitleaksignore` first.

### Tests

`scripts/test-gitleaks-shared.sh .github/workflows/gitleaks-reusable.yml` runs
the scan step against throwaway repositories, with tokens generated at run time
(needs gitleaks at the pinned version, `jq`, and `python3` with PyYAML). CI runs
it on every change to the workflow or the test.

### Known limits

- New commits only; history is not rescanned.
- A required check is matched by name, so another workflow could report a
  passing job of the same name. Require review of `.github/workflows/`.
- A squash merge changes commit ids, so an allow-listed finding can be reported
  again by the push scan on the default branch. It is loud, not silent.

## Licence

MIT. See `LICENSE`.
