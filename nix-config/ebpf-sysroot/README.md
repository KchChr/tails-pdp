# Quellen für den Offline-eBPF-Build

`Cargo.lock` ist die unveränderte Abhängigkeitsliste der Rust-Systembibliothek
aus [Rust-Commit 86a49fd71](https://github.com/rust-lang/rust/blob/86a49fd71/library/Cargo.lock).
Sie gehört zu `nightly-2026-01-15`, der in `../ebpf-toolchain` festgelegten
Toolchain. Auch bei `-Z build-std=core` löst Cargo weitere Teile dieses
Sysroot-Workspaces auf; die Projektabhängigkeiten allein reichen nicht aus.

`registry.json` hält die exakten Versionen und Archivprüfsummen aller 40
Registry-Pakete dieses Lockfiles fest. Ihre Quellen liegen vollständig unter
`../../vendor/`. Die Archive wurden vor dem Entpacken anhand der im Rust-Lockfile
angegebenen SHA-256-Prüfsummen geprüft. Vorhandene Paketversionen wurden erhalten.
Lizenzen und weitere Dateien der Originalpakete bleiben enthalten.

`scripts/check-vendor.py` prüft sowohl die Dateien der einzelnen Pakete als auch
die Vollständigkeit dieser Paketliste. Mit `--sysroot-lock` prüft es zusätzlich,
ob die installierte `rust-src`-Komponente dieselbe Abhängigkeitsliste verwendet.
Der Demo-Build lädt keine fehlenden Pakete nach.

Diese Quellen ersetzen nicht die benötigten Compiler und Systemwerkzeuge und
heben die Nightly-Anforderung des aktuellen Aya-eBPF-Builds nicht auf.
