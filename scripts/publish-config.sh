#!/usr/bin/env bash

# Publish one prepared configuration file; validation/activation remain asynchronous.
set -euo pipefail

if [[ $# -ne 2 ]]; then
    echo "Usage: bash $0 SOURCE DESTINATION (.policy or .attributes)" >&2
    exit 1
fi

source_file="$1"
destination="$2"
# Prefix relative paths so filenames beginning with '-' are never options.
[[ "$source_file" == /* ]] || source_file="./$source_file"
[[ "$destination" == /* ]] || destination="./$destination"

case "$destination" in
    *.policy|*.attributes) ;;
    *) echo "Destination must end in .policy or .attributes." >&2; exit 1 ;;
esac
if [[ ! -f "$source_file" || ! -r "$source_file" ]]; then
    echo "Source must be a readable, complete file: $source_file" >&2
    exit 1
fi
if [[ -L "$destination" || ( -e "$destination" && ! -f "$destination" ) ]]; then
    echo "Destination must be a regular file, not a symlink or directory." >&2
    exit 1
fi

permission_reference="$source_file"
[[ ! -e "$destination" ]] || permission_reference="$destination"
# GNU stat on Linux, BSD stat on macOS. Preserve rwx bits, not special mode bits.
if permission_mode=$(stat -c '%a' "$permission_reference" 2>/dev/null); then
    :
else
    permission_mode=$(stat -f '%Lp' "$permission_reference")
fi
printf -v permission_mode '%03o' "$((8#$permission_mode & 0777))"

parent_directory=$(dirname -- "$destination")
mkdir -p -- "$parent_directory"
temporary_file=""
cleanup() {
    [[ -z "$temporary_file" ]] || rm -f -- "$temporary_file"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

# The random suffix has no active configuration extension. Same-directory staging
# ensures mv performs a rename on the same filesystem, rather than copy-and-delete.
temporary_file=$(mktemp "$parent_directory/.publish-config.tmp.XXXXXXXX")
cat -- "$source_file" > "$temporary_file"
chmod "$permission_mode" "$temporary_file"
mv -f -- "$temporary_file" "$destination"
temporary_file=""
echo "Published $destination; runtime validation/activation is asynchronous."
