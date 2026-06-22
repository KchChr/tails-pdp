Example structured stream attributes for `tails-pdp`.

These files are not loaded automatically from `examples/`. To use them on a target system, copy the
contents of this directory to the runtime `attributes/` directory:

```sh
cp -R examples/attributes/. attributes/
```

`system.attributes` contains system-wide attributes. `subjects/<uid>.attributes` contains attributes for one
subject UID. `resources/<path>.attributes` contains attributes for one file resource, where `<path>` is
the absolute resource path without the leading `/`.
