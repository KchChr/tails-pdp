Example structured stream attributes for `tails-pdp`.

These files are not loaded automatically from `examples/`. Before starting the runtime,
you can copy this directory into `attributes/`:

```sh
cp -R examples/attributes/. attributes/
```

For updates while the runtime is running, publish each prepared file atomically instead:

```sh
bash scripts/publish-config.sh examples/attributes/system.attributes attributes/system.attributes
```

Use the corresponding destination under `attributes/subjects/` or `attributes/resources/`
for the other files. Each publication is independent; multiple files are not one transaction.

`system.attributes` contains system-wide attributes. `subjects/<uid>.attributes` contains attributes for one
subject UID. `resources/<path>.attributes` contains attributes for one file resource, where `<path>` is
the absolute resource path without the leading `/`.

The UID 1000 example has `access-level = 2`. The previous example with
`access-level = 3` is preserved in `../subject-variants/access-level-3/1000.attributes`.
To activate that variant, publish it to `attributes/subjects/1000.attributes` from
the repository root:

```sh
bash scripts/publish-config.sh examples/subject-variants/access-level-3/1000.attributes attributes/subjects/1000.attributes
```
