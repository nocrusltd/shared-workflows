#!/bin/bash
# Runs the workflow's own "Scan the new commits" script against throwaway repos.
# Usage: scripts/test-gitleaks-shared.sh .github/workflows/gitleaks-reusable.yml.  Needs: gitleaks (same version as the workflow), jq, python3+yaml.
# The planted value is generated at run time, lives only in a temp dir, and is never printed.
set -u
WF="$(cd "$(dirname "$1")" && pwd)/$(basename "$1")"; GLBIN=${GLBIN:-$(dirname "$(command -v gitleaks)")}
T=$(mktemp -d); trap 'rm -rf "$T"' EXIT
python3 - "$WF" > "$T/scan.sh" <<'PY'
import yaml,sys
d=yaml.safe_load(open(sys.argv[1]))
steps=d['jobs']['gitleaks']['steps']
s=[x for x in steps if x.get('name','')=='Scan the new commits'][0]
print(s['run'])
PY
python3 - "$WF" > "$T/config.sh" <<'PY'
import yaml,sys
d=yaml.safe_load(open(sys.argv[1]))
s=[x for x in d['jobs']['gitleaks']['steps'] if x.get('name','').startswith('Scan configuration')][0]
print("export GITLEAKS_VERSION=%s GITLEAKS_CONFIG_SHA256=%s" % (s['env']['GITLEAKS_VERSION'], s['env']['GITLEAKS_CONFIG_SHA256']))
print(s['run'])
PY
mkdir -p "$T/shim" "$T/cfg"; printf '#!/bin/bash\nexec shasum -a 256 "$@"\n' > "$T/shim/sha256sum"; chmod +x "$T/shim/sha256sum"
command -v sha256sum >/dev/null || export PATH="$T/shim:$PATH"
( export RUNNER_TEMP="$T/cfg"; bash "$T/config.sh" ) > "$T/config.out" 2>&1 || { echo "FAIL: configuration step failed"; cat "$T/config.out"; exit 1; }
echo "ok   configuration step built the scan configuration ($(wc -l < "$T/cfg/gitleaks.toml" | tr -d ' ') lines)"
# the same step must refuse a default file that is not the pinned one
( export RUNNER_TEMP="$T/cfg2"; mkdir -p "$T/cfg2"; sed 's/GITLEAKS_CONFIG_SHA256=[0-9a-f]*/GITLEAKS_CONFIG_SHA256=0000000000000000000000000000000000000000000000000000000000000000/' "$T/config.sh" > "$T/config-bad.sh"; bash "$T/config-bad.sh" ) >/dev/null 2>&1 && { echo "FAIL: configuration step accepted a wrong checksum"; exit 1; } || echo "ok   configuration step refuses a wrong checksum"
want=$(python3 -c "import yaml,sys; d=yaml.safe_load(open('$WF')); print([x for x in d['jobs']['gitleaks']['steps'] if x.get('name','').startswith('Install')][0]['env']['GITLEAKS_VERSION'])")
have=$("$GLBIN/gitleaks" version); [ "$want" = "$have" ] || { echo "FAIL: local gitleaks $have != workflow $want"; exit 1; }
SECRET="ghp_$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)"
mk() { rm -rf "$T/r"; mkdir "$T/r"; cd "$T/r"; git init -q -b main; git config user.email t@example.invalid; git config user.name t; git config core.autocrlf false; echo hello > a.txt; git add .; git commit -qm base; }
run() { # event base head before after
  ( cd "$T/r"; export PATH="$GLBIN:$PATH" RUNNER_TEMP="$T/rt" GITHUB_STEP_SUMMARY="$T/summary.md" EVENT_NAME="$1" PR_BASE_SHA="$2" PR_HEAD_SHA="$3" PUSH_BEFORE="$4" PUSH_AFTER="$5" GITHUB_SHA="$5"
    mkdir -p "$RUNNER_TEMP"; cp "$T/cfg/gitleaks.toml" "$RUNNER_TEMP/gitleaks.toml"; : > "$GITHUB_STEP_SUMMARY"; bash "$T/scan.sh" > "$T/out.txt" 2>&1; rc=$?; [ -n "${DEBUG:-}" ] && tail -5 "$T/out.txt" >&2; echo $rc ) }
fail=0; check() { if [ "$2" = "$3" ]; then echo "ok   $1 (exit $2)"; else echo "FAIL $1: exit $2, expected $3"; fail=1; fi; }
mk; b=$(git rev-parse HEAD); echo more >> a.txt; git commit -qam clean; h=$(git rev-parse HEAD)
check "PR (pull_request_target), clean commit passes" "$(run pull_request_target $b $h '' $h)" 0
check "PR (pull_request), clean commit passes" "$(run pull_request $b $h '' $h)" 0
check "push, clean commit passes" "$(run push '' '' $b $h)" 0
mk; b=$(git rev-parse HEAD); printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
check "PR, planted token is blocked" "$(run pull_request $b $h '' $h)" 2
if grep -qF "$SECRET" "$T/out.txt" "$T/summary.md" "$T/rt/gitleaks-report.json" 2>/dev/null; then echo "FAIL value appears in log, summary or report"; fail=1; else echo "ok   value absent from log, summary and report"; fi
grep -q 'cfg.txt' "$T/summary.md" && echo "ok   summary names rule and file" || { echo "FAIL summary lacks the file"; fail=1; }
check "push, planted token is blocked" "$(run push '' '' $b $h)" 2
git rm -q cfg.txt; git commit -qm removed; h2=$(git rev-parse HEAD)
check "PR, secret added then removed in the range is still blocked" "$(run pull_request $b $h2 '' $h2)" 2
check "push range after the secret commit passes (not re-scanned)" "$(run push '' '' $h $h2)" 0
check "push with no usable previous tip fails closed" "$(run push '' '' 0000000000000000000000000000000000000000 $h2)" 1
check "PR with a base commit not in the clone fails closed" "$(run pull_request 1111111111111111111111111111111111111111 $h2 '' $h2)" 1
# file types the default configuration skips by name
for f in credentials.bin notes.pdf tool.exe logo.png font.woff2; do
  mk; b=$(git rev-parse HEAD); printf 'token = "%s"\n' "$SECRET" > "$f"; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
  check "PR, token in $f is blocked" "$(run pull_request $b $h '' $h)" 2
done
# and the same .bin commit must PASS under the unmodified defaults, proving the configuration step is what catches it
mk; b=$(git rev-parse HEAD); printf 'token = "%s"\n' "$SECRET" > credentials.bin; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
sed '/--config "$RUNNER_TEMP\/gitleaks.toml"/d' "$T/scan.sh" > "$T/scan-defaults.sh"
grep -q -- '--config "' "$T/scan-defaults.sh" && { echo "FAIL could not build the defaults variant"; fail=1; }
( cd "$T/r"; export PATH="$GLBIN:$PATH" RUNNER_TEMP="$T/rt3" GITHUB_STEP_SUMMARY="$T/s3.md" EVENT_NAME=pull_request PR_BASE_SHA=$b PR_HEAD_SHA=$h PUSH_BEFORE='' PUSH_AFTER=$h; mkdir -p "$RUNNER_TEMP"; bash "$T/scan-defaults.sh" >/dev/null 2>&1; echo $? ) > "$T/rc3"
[ "$(cat "$T/rc3")" = "0" ] && echo "ok   under the unmodified defaults the same .bin commit passes (exit 0): the configuration step has teeth" || { echo "FAIL defaults variant exit $(cat "$T/rc3"), expected 0"; fail=1; }
# still excluded on purpose: lock files
mk; b=$(git rev-parse HEAD); printf 'token = "%s"\n' "$SECRET" > package-lock.json; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
check "PR, token in package-lock.json is NOT flagged (documented exclusion)" "$(run pull_request $b $h '' $h)" 0

# variant runner: run a modified copy of the scan script in the current repo
runv() { # script event base head  -> exit code
  ( cd "$T/r"; export PATH="$GLBIN:$PATH" RUNNER_TEMP="$T/rtv" GITHUB_STEP_SUMMARY="$T/sv.md" EVENT_NAME="$2" PR_BASE_SHA="$3" PR_HEAD_SHA="$4" PUSH_BEFORE='' PUSH_AFTER="$4"; rm -rf "$RUNNER_TEMP"; mkdir -p "$RUNNER_TEMP"; cp "$T/cfg/gitleaks.toml" "$RUNNER_TEMP/gitleaks.toml"; : > "$GITHUB_STEP_SUMMARY"; bash "$1" > "$T/outv.txt" 2>&1; echo $? ) }
co() { git -C "$T/r" checkout -q --detach "$1"; }   # the workflow checks out the PR head
# sed fragment that empties the second (net change) pass, to show what the first pass does by itself
NONET='s/^net_opts=.*/net_opts="--text --no-renames ${net_commit}..${net_commit}"/'
grep -q '^net_opts=' "$T/scan.sh" || { echo "FAIL the scan script has no net_opts line to neutralise"; fail=1; }

# --- an unsupported event fails closed
mk; b=$(git rev-parse HEAD); echo x >> a.txt; git commit -qam c; h=$(git rev-parse HEAD)
check "an unsupported event fails closed" "$(run workflow_dispatch $b $h '' $h)" 1

# --- rename bypass: token added under an excluded name, then renamed to an included one
mk; b=$(git rev-parse HEAD); printf 'token = "%s"\n' "$SECRET" > package-lock.json; git add .; git commit -qm lock
git mv package-lock.json credentials.txt; git commit -qm rename; h=$(git rev-parse HEAD)
check "PR, token moved from package-lock.json to credentials.txt is blocked" "$(run pull_request_target $b $h '' $h)" 2
# two protections catch this, so each is shown by taking the other away
sed -e "$NONET" "$T/scan.sh" > "$T/scan-p1.sh"
rc=$(runv "$T/scan-p1.sh" pull_request_target $b $h)
[ "$rc" = "2" ] && echo "ok   the commit-by-commit pass alone blocks it (exit 2)" || { echo "FAIL first-pass-only exit $rc, expected 2"; fail=1; }
sed -e "$NONET" -e 's/^log_opts="--diff-merges=remerge --text --no-renames /log_opts="--diff-merges=remerge --text /' "$T/scan.sh" > "$T/scan-renames.sh"; grep -q -- '^log_opts=.*--no-renames' "$T/scan-renames.sh" && { echo "FAIL could not build the rename variant"; fail=1; }
rc=$(runv "$T/scan-renames.sh" pull_request_target $b $h)
[ "$rc" = "0" ] && echo "ok   first pass alone without --no-renames passes it (exit 0): the flag has teeth" || { echo "FAIL rename variant exit $rc, expected 0"; fail=1; }

# --- a PR cannot allow-list its own finding
mk; b=$(git rev-parse HEAD); printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
run pull_request_target $b $h '' $h >/dev/null; fp=$(jq -r '[.[]|select(.Commit!="net change")][0].Fingerprint' "$T/rt/gitleaks-report.json")
echo "$fp" > .gitleaksignore; git add .gitleaksignore; git commit -qm self-ignore; h2=$(git rev-parse HEAD)
check "PR, a fingerprint added by the PR itself does NOT suppress the finding" "$(run pull_request_target $b $h2 '' $h2)" 2
git -C "$T/r" checkout -q -- .gitleaksignore 2>/dev/null || true
sed -e "$NONET" -e '/^rm -f \.gitleaksignore$/d' -e '/--gitleaks-ignore-path "\$ignore_dir"/d' "$T/scan.sh" > "$T/scan-treeignore.sh"
grep -qE '^rm -f \.gitleaksignore$|--gitleaks-ignore-path' "$T/scan-treeignore.sh" && { echo "FAIL could not build the tree-ignore variant"; fail=1; }
rc=$(runv "$T/scan-treeignore.sh" pull_request_target $b $h2)
[ "$rc" = "0" ] && echo "ok   reading the ignore file from the scanned tree lets the PR pass (exit 0): reading it from the base has teeth" || { echo "FAIL tree-ignore variant exit $rc, expected 0"; fail=1; }
# only removing the working-tree copy is not enough to explain it: with the flag kept but the rm dropped, gitleaks still reads the tree copy
sed -e "$NONET" -e '/^rm -f \.gitleaksignore$/d' "$T/scan.sh" > "$T/scan-norm.sh"; git -C "$T/r" checkout -q -- . 2>/dev/null; git -C "$T/r" checkout -q "$h2" -- .gitleaksignore
rc=$(runv "$T/scan-norm.sh" pull_request_target $b $h2)
[ "$rc" = "0" ] && echo "ok   without removing the working-tree copy the PR passes (exit 0): the removal has teeth" || { echo "FAIL no-rm variant exit $rc, expected 0"; fail=1; }

# --- the legitimate route: the fingerprint is merged to the base first
mk; b0=$(git rev-parse HEAD); git checkout -q -b feature; printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
run pull_request_target $b0 $h '' $h >/dev/null; fp=$(jq -r '[.[]|select(.Commit!="net change")][0].Fingerprint' "$T/rt/gitleaks-report.json")
git checkout -q main; printf '# reviewed false positive\n%s\n' "$fp" > .gitleaksignore; git add .; git commit -qm allow; b1=$(git rev-parse HEAD); co $h
check "PR, a fingerprint already on the base suppresses that finding" "$(run pull_request_target $b1 $h '' $h)" 0
grep -q 'Using .gitleaksignore from' "$T/out.txt" && echo "ok   log says the base ignore file was used" || { echo "FAIL log does not mention the base ignore file"; fail=1; }

# --- a malformed entry already on the base grants nothing, is not printed, and does not block its own repair
mk; JUNK="not-a-fingerprint $(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 30)"; printf '%s\n' "$JUNK" > .gitleaksignore; git add .; git commit -qm badignore; b=$(git rev-parse HEAD)
git rm -q .gitleaksignore; git commit -qm repair; h=$(git rev-parse HEAD)
check "the pull request that removes a malformed base .gitleaksignore passes" "$(run pull_request_target $b $h '' $h)" 0
if grep -qF "$JUNK" "$T/out.txt" "$T/summary.md" 2>/dev/null; then echo "FAIL the malformed entry's content was printed"; fail=1; else echo "ok   the malformed entry's content is not in the log or summary"; fi
grep -q 'line(s): 1 ' "$T/out.txt" && grep -q 'No exceptions apply' "$T/out.txt" && echo "ok   the log names the line number and says no exceptions apply" || { echo "FAIL log lacks the warning"; fail=1; }
git checkout -q -b leak "$b"; printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add cfg.txt; git commit -qm planted; h=$(git rev-parse HEAD)
check "with a malformed base file a planted token is still blocked" "$(run pull_request_target $b $h '' $h)" 2
# The whole file is refused, not just the bad line: a VALID exception for this very token, sitting beside a
# malformed entry on the base, must grant nothing either. (Built like the legitimate route above: the token
# commit exists first, so its real fingerprint can be put on the base.)
mk; b0=$(git rev-parse HEAD); git checkout -q -b leak2; printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
run pull_request_target $b0 $h '' $h >/dev/null; fp=$(jq -r '[.[]|select(.Commit!="net change")][0].Fingerprint' "$T/rt/gitleaks-report.json")
[ -n "$fp" ] && [ "$fp" != "null" ] || { echo "FAIL could not read the planted token's fingerprint"; fail=1; }
git checkout -q main; printf '%s\n%s\n' "$JUNK" "$fp" > .gitleaksignore; git add .; git commit -qm bad-plus-valid; b1=$(git rev-parse HEAD); co $h
check "a valid exception beside a malformed base entry grants nothing: the token is still blocked" "$(run pull_request_target $b1 $h '' $h)" 2
# and the same valid exception alone does suppress it, so the case above fails for the malformed line and nothing else
git checkout -q main; printf '%s\n' "$fp" > .gitleaksignore; git add .; git commit -qm valid-only; b2=$(git rev-parse HEAD); co $h
check "the same exception without the malformed line suppresses the finding" "$(run pull_request_target $b2 $h '' $h)" 0

# --- the base repaired a malformed file after the branch was cut: the branch did not change it and must pass
mk; printf 'not a fingerprint\n' > .gitleaksignore; git add .; git commit -qm badignore; A=$(git rev-parse HEAD)
git checkout -q -b topic; echo doc > README.md; git add .; git commit -qm readme; h=$(git rev-parse HEAD)
git checkout -q main; git rm -q .gitleaksignore; git commit -qm repaired-on-main; B=$(git rev-parse HEAD); co $h
check "PR cut before the base repaired its .gitleaksignore is not failed for the old copy" "$(run pull_request_target $B $h '' $h)" 0
python3 - "$T/scan.sh" "$T/scan-cmpbase.sh" <<'PY'
import sys
s=open(sys.argv[1]).read(); a='changed_from="$(git merge-base "$trusted" "$proposed" || true)"'
assert a in s, "scan script changed; update the compare-with-base variant"
open(sys.argv[2],"w").write(s.replace(a,'changed_from="$trusted"'))
PY
[ -s "$T/scan-cmpbase.sh" ] && ! cmp -s "$T/scan.sh" "$T/scan-cmpbase.sh" && bash -n "$T/scan-cmpbase.sh" || { echo "FAIL could not build the compare-with-base variant"; exit 1; }
rc=$(runv "$T/scan-cmpbase.sh" pull_request_target $B $h)
[ "$rc" = "1" ] && echo "ok   comparing with the current base instead fails that pull request (exit 1): the merge-base comparison has teeth" || { echo "FAIL compare-with-base variant exit $rc, expected 1"; fail=1; }

# --- a malformed entry in the commits being scanned is refused, and its content is not printed
mk; b=$(git rev-parse HEAD); JUNK="not-a-fingerprint $(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 30)"; printf '%s\n' "$JUNK" > .gitleaksignore; git add .; git commit -qm badignore; h=$(git rev-parse HEAD)
check "a pull request that adds a malformed .gitleaksignore fails" "$(run pull_request_target $b $h '' $h)" 1
if grep -qF "$JUNK" "$T/out.txt" "$T/summary.md" 2>/dev/null; then echo "FAIL the proposed malformed entry's content was printed"; fail=1; else echo "ok   the proposed malformed entry's content is not printed"; fi

# --- a valid entry with Windows line endings on the base is accepted
mk; b0=$(git rev-parse HEAD); git checkout -q -b feature; printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
run pull_request_target $b0 $h '' $h >/dev/null; fp=$(jq -r '[.[]|select(.Commit!="net change")][0].Fingerprint' "$T/rt/gitleaks-report.json")
git checkout -q main; printf '# reviewed\r\n%s\r\n' "$fp" > .gitleaksignore; git add .; git commit -qm allow-crlf; b1=$(git rev-parse HEAD); co $h
git cat-file -p "$b1:.gitleaksignore" | grep -q $'\r' || { echo "FAIL the base ignore file was not committed with CRLF"; fail=1; }
check "PR, a base fingerprint with CRLF line endings suppresses that finding" "$(run pull_request_target $b1 $h '' $h)" 0
# the earlier form of the check (no CR handling, no trailing white space allowed) rejects that entry, so no exception applies
python3 - "$T/scan.sh" "$T/scan-crlf.sh" <<'PY'
import sys
s=open(sys.argv[1]).read()
a="tr -d '\\r' < \"$1\" | grep"; b=":[0-9]+[[:space:]]*$'"; c="| tr -d '\\r' > \"$ignore_dir/.gitleaksignore\""
assert a in s and b in s and c in s, "scan script changed; update the CRLF variant"
open(sys.argv[2],"w").write(s.replace(a,"cat \"$1\" | grep").replace(b,":[0-9]+$'").replace(c,"> \"$ignore_dir/.gitleaksignore\""))
PY
[ -s "$T/scan-crlf.sh" ] && ! cmp -s "$T/scan.sh" "$T/scan-crlf.sh" && bash -n "$T/scan-crlf.sh" || { echo "FAIL could not build the CRLF variant"; exit 1; }
rc=$(runv "$T/scan-crlf.sh" pull_request_target $b1 $h)
[ "$rc" = "2" ] && echo "ok   with the earlier check the CRLF entry is rejected and the finding returns (exit 2): the handling has teeth" || { echo "FAIL CRLF variant exit $rc, expected 2"; fail=1; }

# --- a base ignore file holding only comments must not end the step
mk; printf '# nothing allow-listed yet\n\n' > .gitleaksignore; git add .; git commit -qm comment-only; b=$(git rev-parse HEAD); echo z >> a.txt; git commit -qam c; h=$(git rev-parse HEAD)
check "a comment-only base .gitleaksignore: clean pull request passes" "$(run pull_request_target $b $h '' $h)" 0
grep -q 'No secrets found' "$T/summary.md" && echo "ok   and the summary is written" || { echo "FAIL summary was not written"; fail=1; }
python3 - "$T/scan.sh" "$T/scan-grepv.sh" <<'PY'
import sys
s=open(sys.argv[1]).read()
a="sed -E '/^[[:space:]]*(#.*)?$/d; s/[[:space:]]+$//; s/^[0-9a-f]{7,64}://; s#\\\\#/#g' \"$ignore_dir/.gitleaksignore\" |"
assert a in s, "scan script changed; update the comment-only variant"
open(sys.argv[2],"w").write(s.replace(a,"grep -vE '^[[:space:]]*(#.*)?$' \"$ignore_dir/.gitleaksignore\" | sed -E 's/[[:space:]]+$//; s/^[0-9a-f]{7,64}://' |"))
PY
[ -s "$T/scan-grepv.sh" ] && ! cmp -s "$T/scan.sh" "$T/scan-grepv.sh" && bash -n "$T/scan-grepv.sh" || { echo "FAIL could not build the comment-only variant"; exit 1; }
rc=$(runv "$T/scan-grepv.sh" pull_request_target $b $h)
[ "$rc" = "1" ] && ! grep -q 'No secrets found' "$T/sv.md" && echo "ok   the earlier grep form ends the step on that file before the summary (exit 1): the change has teeth" || { echo "FAIL grep variant exit $rc, expected 1 with no summary"; fail=1; }

# --- an entry gitleaks would print in full (wrong number of fields) is refused
mk; b=$(git rev-parse HEAD); JUNK="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 30):a:b:generic-api-key:1"; printf '%s\n' "$JUNK" > .gitleaksignore; git add .; git commit -qm fivefields; h=$(git rev-parse HEAD)
check "a five-field .gitleaksignore entry in the commits fails" "$(run pull_request_target $b $h '' $h)" 1
echo q >> a.txt; git commit -qam next; h2=$(git rev-parse HEAD)
check "a five-field entry already on the base grants nothing and the scan goes ahead" "$(run pull_request_target $h $h2 '' $h2)" 0
if grep -qF "${JUNK%%:*}" "$T/out.txt" "$T/summary.md" 2>/dev/null; then echo "FAIL the five-field entry's content was printed"; fail=1; else echo "ok   the five-field entry's content is not printed"; fi

# --- a NUL byte makes grep treat the file as binary and report nothing: such a file is refused whole
mk; b=$(git rev-parse HEAD); CAN="$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 30)"; printf '#\0\n%s:a:b:github-pat:1\n' "$CAN" > .gitleaksignore; git add .; git commit -qm nul; h=$(git rev-parse HEAD)
git cat-file -p "$h:.gitleaksignore" | LC_ALL=C tr -d -c '\000' | wc -c | grep -q '1' || { echo "FAIL the NUL test file has no NUL byte"; exit 1; }
check "a .gitleaksignore containing a NUL byte in the commits fails" "$(run pull_request_target $b $h '' $h)" 1
grep -q 'NUL bytes' "$T/out.txt" && echo "ok   the log says why" || { echo "FAIL log does not mention NUL bytes"; fail=1; }
echo q >> a.txt; git commit -qam next; h2=$(git rev-parse HEAD)
check "one already on the base grants nothing and the scan goes ahead" "$(run pull_request_target $h $h2 '' $h2)" 0
grep -q 'No exceptions apply' "$T/out.txt" && echo "ok   and the log says no exceptions apply" || { echo "FAIL no warning for the NUL base file"; fail=1; }
if grep -aqF "$CAN" "$T/out.txt" "$T/summary.md" 2>/dev/null; then echo "FAIL the entry beside the NUL byte was printed"; fail=1; else echo "ok   the entry beside the NUL byte is not printed"; fi
python3 - "$T/scan.sh" "$T/scan-nonul.sh" <<'PY'
import sys,re
s=open(sys.argv[1]).read()
m=re.search(r"\n[ \t]*if \[ \"\$\(tr -d '\\000' < \"\$1\" \| wc -c\)\" -ne [^\n]*\n", s)
assert m and "grep -anvE" in s, "scan script changed; update the NUL variant"
open(sys.argv[2],"w").write((s[:m.start()]+"\n"+s[m.end():]).replace("grep -anvE","grep -nvE"))
PY
[ -s "$T/scan-nonul.sh" ] && ! cmp -s "$T/scan.sh" "$T/scan-nonul.sh" && bash -n "$T/scan-nonul.sh" || { echo "FAIL could not build the NUL variant"; exit 1; }
if grep --version 2>/dev/null | head -1 | grep -q 'GNU grep'; then
  rc=$(runv "$T/scan-nonul.sh" pull_request_target $b $h)
  [ "$rc" = "0" ] && echo "ok   without the NUL check GNU grep lets that file through (exit 0): the check has teeth" || { echo "FAIL NUL variant exit $rc, expected 0"; fail=1; }
else
  echo "ok   (control for the NUL check not run: it shows the gap only with GNU grep, which CI uses; this grep is $(grep --version 2>/dev/null | head -1))"
fi

# --- the base removed an old token after the branch was cut: the pull request adds nothing and must pass
mk; printf 'token = "%s"\n' "$SECRET" > application.txt; git add .; git commit -qm old; A=$(git rev-parse HEAD)
git checkout -q -b topic; echo doc > README.md; git add .; git commit -qm readme; h=$(git rev-parse HEAD)
git checkout -q main; git rm -q application.txt; git commit -qm removed-on-main; B=$(git rev-parse HEAD); co $h
check "PR behind a base that removed an old token is not blamed for it" "$(run pull_request_target $B $h '' $h)" 0
python3 - "$T/scan.sh" "$T/scan-headtree.sh" <<'PY'
import sys
s=open(sys.argv[1]).read(); a='net_tree="$merged"'
assert a in s, "scan script changed; update the head-tree variant"
open(sys.argv[2],"w").write(s.replace(a,'net_tree="${proposed}^{tree}"'))
PY
[ -s "$T/scan-headtree.sh" ] && ! cmp -s "$T/scan.sh" "$T/scan-headtree.sh" && bash -n "$T/scan-headtree.sh" || { echo "FAIL could not build the head-tree variant"; exit 1; }
rc=$(runv "$T/scan-headtree.sh" pull_request_target $B $h)
[ "$rc" = "2" ] && echo "ok   scanning the head's own tree against the base blames it (exit 2): using the merge result has teeth" || { echo "FAIL head-tree variant exit $rc, expected 2"; fail=1; }

# --- the base renamed an excluded file after the branch was cut; the pull request adds a token under the old name
mk; printf 'lock v1\n' > package-lock.json; git add .; git commit -qm lock; A=$(git rev-parse HEAD)
git checkout -q -b topic; printf 'token = "%s"\n' "$SECRET" >> package-lock.json; git commit -qam token; h=$(git rev-parse HEAD)
git checkout -q main; git mv package-lock.json application.txt; git commit -qm renamed-on-main; B=$(git rev-parse HEAD); co $h
check "PR token that the merge would move from an excluded name to an included path is blocked" "$(run pull_request_target $B $h '' $h)" 2
rc=$(runv "$T/scan-headtree.sh" pull_request_target $B $h)
[ "$rc" = "0" ] && echo "ok   scanning the head's own tree misses it (exit 0): using the merge result has teeth" || { echo "FAIL head-tree variant exit $rc, expected 0"; fail=1; }

# --- a pull request that conflicts with its base is still scanned (head against the merge base)
mk; echo one > c.txt; git add .; git commit -qm c; A=$(git rev-parse HEAD)
git checkout -q -b topic; echo topic > c.txt; printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm topic; h=$(git rev-parse HEAD)
git checkout -q main; echo main > c.txt; git commit -qam main; B=$(git rev-parse HEAD); co $h
check "a conflicting pull request with a planted token is blocked" "$(run pull_request_target $B $h '' $h)" 2
grep -q 'does not merge cleanly' "$T/out.txt" && echo "ok   and the log says the merge base was used" || { echo "FAIL no notice about the conflict fallback"; fail=1; }

# --- a base entry written with a backslash path (as copied on Windows) still applies to both passes
mk; b0=$(git rev-parse HEAD); git checkout -q -b feature; mkdir src; printf 'token = "%s"\n' "$SECRET" > src/app.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
run pull_request_target $b0 $h '' $h >/dev/null; fp=$(jq -r '[.[]|select(.Commit!="net change")][0].Fingerprint' "$T/rt/gitleaks-report.json")
case "$fp" in *:src/app.txt:*) ;; *) echo "FAIL unexpected fingerprint shape for the backslash case"; exit 1;; esac
git checkout -q main; printf '%s\n' "$fp" | sed 's#src/app.txt#src\\app.txt#' > .gitleaksignore; grep -q 'src\\app.txt' .gitleaksignore || { echo "FAIL could not write the backslash entry"; exit 1; }
git add .; git commit -qm allow-backslash; b1=$(git rev-parse HEAD); co $h
check "PR, a base entry with a backslash path suppresses the finding in both passes" "$(run pull_request_target $b1 $h '' $h)" 0
python3 - "$T/scan.sh" "$T/scan-noslash.sh" <<'PY'
import sys
s=open(sys.argv[1]).read(); a="; s#\\\\#/#g'"
assert a in s, "scan script changed; update the backslash variant"
open(sys.argv[2],"w").write(s.replace(a,"'"))
PY
[ -s "$T/scan-noslash.sh" ] && ! cmp -s "$T/scan.sh" "$T/scan-noslash.sh" && bash -n "$T/scan-noslash.sh" || { echo "FAIL could not build the backslash variant"; exit 1; }
rc=$(runv "$T/scan-noslash.sh" pull_request_target $b1 $h)
[ "$rc" = "2" ] && echo "ok   without the normalisation the net-change pass reports it again (exit 2): the change has teeth" || { echo "FAIL backslash variant exit $rc, expected 2"; fail=1; }

# --- a token that reaches a scanned path only through a merge
mk; printf 'lock v1\n' > package-lock.json; git add .; git commit -qm lock; b=$(git rev-parse HEAD)
git checkout -q -b ren; git mv package-lock.json application.txt; git commit -qm rename
git checkout -q -b tok "$b"; printf 'token = "%s"\n' "$SECRET" >> package-lock.json; git commit -qam token
git checkout -q ren; git merge -q --no-edit tok >/dev/null 2>&1; h=$(git rev-parse HEAD)
grep -qF "$SECRET" application.txt && [ "$(git rev-list --parents -n1 HEAD | wc -w | tr -d ' ')" = "3" ] || { echo "FAIL could not build the merge scenario"; fail=1; }
check "PR, token merged from an excluded file into an included path is blocked" "$(run pull_request_target $b $h '' $h)" 2
grep -q 'net change' "$T/summary.md" && echo "ok   summary marks it as a net-change finding" || { echo "FAIL summary does not mark the net-change finding"; fail=1; }
if grep -qF "$SECRET" "$T/out.txt" "$T/summary.md" "$T/rt/gitleaks-report.json" "$T/rt/gitleaks-report-net.json" 2>/dev/null; then echo "FAIL value appears in log, summary or a report"; fail=1; else echo "ok   value absent from log, summary and both reports"; fi
sed -e "$NONET" "$T/scan.sh" > "$T/scan-nonet.sh"
rc=$(runv "$T/scan-nonet.sh" pull_request_target $b $h)
[ "$rc" = "0" ] && echo "ok   without the net-change pass the same merge passes (exit 0): that pass has teeth" || { echo "FAIL no-net variant exit $rc, expected 0"; fail=1; }

# --- a .gitleaks.toml in the scanned commits cannot switch the rules off
mk; b=$(git rev-parse HEAD); printf 'title = "x"\n[allowlist]\npaths = [".*"]\n' > .gitleaks.toml; printf 'token = "%s"\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
check "PR, a .gitleaks.toml in the PR that allow-lists every path does not suppress the finding" "$(run pull_request_target $b $h '' $h)" 2
sed '/--config "$RUNNER_TEMP\/gitleaks.toml"/d' "$T/scan.sh" > "$T/scan-noconfig.sh"
rc=$(runv "$T/scan-noconfig.sh" pull_request_target $b $h)
[ "$rc" = "0" ] && echo "ok   without the explicit configuration that file is honoured (exit 0): the explicit configuration has teeth" || { echo "FAIL no-config variant exit $rc, expected 0"; fail=1; }

# --- the summary table is capped
mk; b=$(git rev-parse HEAD); for i in $(seq 1 60); do printf 'token = "ghp_%s"\n' "$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 36)" > "f$i.txt"; done; git add .; git commit -qm many; h=$(git rev-parse HEAD)
check "PR with 60 findings is blocked" "$(run pull_request_target $b $h '' $h)" 2
rows=$(grep -c '^| [a-z]' "$T/summary.md"); total=$(grep -oE '^\*\*[0-9]+ finding' "$T/summary.md" | grep -oE '[0-9]+')
[ "$rows" = "50" ] && [ "$total" = "60" ] && grep -q 'Only the first 50' "$T/summary.md" && echo "ok   summary reports 60 and lists 50 rows" || { echo "FAIL summary rows=$rows total=$total"; fail=1; }

# an inline "gitleaks:allow" comment must not suppress a finding
mk; b=$(git rev-parse HEAD); printf 'token = "%s" # gitleaks:allow\n' "$SECRET" > cfg.txt; git add .; git commit -qm planted; h=$(git rev-parse HEAD)
check "PR, token with an inline gitleaks:allow comment is still blocked" "$(run pull_request $b $h '' $h)" 2
sed '/--ignore-gitleaks-allow/d' "$T/scan.sh" > "$T/scan-inline.sh"
( cd "$T/r"; export PATH="$GLBIN:$PATH" RUNNER_TEMP="$T/rt4" GITHUB_STEP_SUMMARY="$T/s4.md" EVENT_NAME=pull_request PR_BASE_SHA=$b PR_HEAD_SHA=$h PUSH_BEFORE='' PUSH_AFTER=$h; mkdir -p "$RUNNER_TEMP"; cp "$T/cfg/gitleaks.toml" "$RUNNER_TEMP/gitleaks.toml"; bash "$T/scan-inline.sh" >/dev/null 2>&1; echo $? ) > "$T/rc4"
[ "$(cat "$T/rc4")" = "0" ] && echo "ok   without the flag the inline comment suppresses it (exit 0): the flag has teeth" || { echo "FAIL inline variant exit $(cat "$T/rc4"), expected 0"; fail=1; }
# teeth: the same planted commit must PASS when the scan line is neutralised, proving the block comes from gitleaks.
sed 's/gitleaks git \. \\/true \\/' "$T/scan.sh" > "$T/scan-broken.sh"
grep -q 'gitleaks git \. ' "$T/scan-broken.sh" && { echo "FAIL could not build the no-scanner variant"; fail=1; }
rc=$(runv "$T/scan-broken.sh" pull_request_target $b $h)
[ "$rc" = "0" ] && echo "ok   with both scanner calls replaced by a no-op the planted commit passes (exit 0): the test has teeth" || { echo "FAIL no-scanner variant exit $rc, expected 0"; fail=1; }
exit $fail
