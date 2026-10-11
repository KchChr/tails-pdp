#!/usr/bin/env bash

set -euo pipefail
project_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
test_directory=$(mktemp -d "${TMPDIR:-/tmp}/tails-pdp-publish.XXXXXXXX")
trap 'rm -rf -- "$test_directory"' EXIT
publisher="$project_root/scripts/publish-config.sh"

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_no_staging_files() {
    local files=("$test_directory"/.publish-config.tmp.*)
    [[ ! -e "${files[0]}" ]] || fail "staging file left behind"
}

# Replacement publishes complete bytes and leaves an existing reader on the old file.
printf 'complete new policy\n' > "$test_directory/prepared"
printf 'old policy\n' > "$test_directory/active.policy"
chmod 640 "$test_directory/active.policy"
exec 3< "$test_directory/active.policy"
bash "$publisher" "$test_directory/prepared" "$test_directory/active.policy" >/dev/null
cmp "$test_directory/prepared" "$test_directory/active.policy" || fail "wrong contents"
IFS= read -r old_contents <&3
exec 3<&-
[[ "$old_contents" == 'old policy' ]] || fail "old reader switched file"
mode=$(stat -c '%a' "$test_directory/active.policy" 2>/dev/null) \
    || mode=$(stat -f '%Lp' "$test_directory/active.policy")
[[ "$mode" == 640 ]] || fail "destination permissions changed"
assert_no_staging_files

# Simulate a rename failure without root/filesystem assumptions.
mkdir "$test_directory/bin"
printf '#!/usr/bin/env bash\nexit 1\n' > "$test_directory/bin/mv"
chmod +x "$test_directory/bin/mv"
printf 'replacement must fail\n' > "$test_directory/prepared"
if PATH="$test_directory/bin:$PATH" bash "$publisher" \
    "$test_directory/prepared" "$test_directory/active.policy" >/dev/null 2>&1; then
    fail "failed rename reported success"
fi
[[ "$(cat "$test_directory/active.policy")" == 'complete new policy' ]] || fail "failed rename changed target"
assert_no_staging_files

# Nested attributes and paths containing spaces; invalid destinations are rejected.
bash "$publisher" "$test_directory/prepared" "$test_directory/subjects with spaces/1000.attributes" >/dev/null
cmp "$test_directory/prepared" "$test_directory/subjects with spaces/1000.attributes" || fail "nested publication failed"
ln -s "$test_directory/active.policy" "$test_directory/linked.policy"
mkdir "$test_directory/directory.policy"
for rejected in linked.policy directory.policy invalid.txt; do
    if bash "$publisher" "$test_directory/prepared" "$test_directory/$rejected" >/dev/null 2>&1; then
        fail "accepted invalid destination: $rejected"
    fi
done
echo "Publication checks passed (replacement, permissions, rollback, cleanup, nested paths, invalid targets)."
