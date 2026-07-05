This directory contains SAPL-inspired example policies for `tails-pdp`.

These files are not loaded automatically. To activate a policy, copy it into `../policies/`.

Each `.policy` file contains exactly one simple policy. More complex behavior is expressed by using
multiple files, for example one policy for `hour < 8` and another for `hour >= 16`.

Stream policies may use the same static hook filters as static policies, for example `command`,
`subject.uid` or `resource.path`, plus stream conditions such as `environment.utc.hour`,
`system.<attribute>`, `subject.<attribute>` or `resource.<attribute>`.

Numbering convention:

- `10-*` to `19-*`: `file_open` policies

DEFCON examples use `system.defcon`. The current DEFCON value is read from
`../attributes/system.attributes` and must be an integer from `1` to `5`.

Structured attribute examples are stored in `attributes/`. These files are not loaded from the
example directory automatically; copy them into the runtime `../attributes/` directory before
starting `tails-pdp` if you want to try policies that reference `system.<attribute>` or
`subject.<attribute>` or `resource.<attribute>`.
