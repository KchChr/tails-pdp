This directory contains SAPL-inspired example policies for `tails-pdp`.

These files are not loaded automatically. To activate a policy, copy it into `../policies/`.

Each `.sapl` file contains exactly one simple policy. More complex behavior is expressed by using
multiple files, for example one policy for `hour < 8` and another for `hour >= 16`.

Numbering convention:

- `10-*` to `19-*`: `file_open` policies
- `20-*` to `29-*`: `socket_bind` policies

DEFCON stream examples use `environment.defcon.level`. The current test DEFCON value is read from
`../stream-attributes/DEFCON.txt` and must be an integer from `1` to `5`.
