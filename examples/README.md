This directory contains SAPL-inspired example policies for `tails-pdp`.

These files are not loaded automatically. To activate a policy, copy it into `../policies/`.

Each `.sapl` file contains exactly one simple policy. More complex behavior is expressed by using
multiple files, for example one policy for `hour < 8` and another for `hour >= 16`.
