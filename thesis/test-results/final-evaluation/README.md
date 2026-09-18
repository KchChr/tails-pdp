# Nachweise für Kapitel 6 und 7

Vollständiger Lauf von `nix-shell nix-config/shell.nix --run "bash ./test.sh"`
auf dem dedizierten NixOS-Testsystem. Exitstatus: 0.

- `full-suite.log`: Formatprüfung, 61 Rust-Tests, sechs Python-Tests, Clippy, Release-Build und Systemtests.
- `e2e-report.json`: E2E-11 bis E2E-19; E2E-01 bis E2E-10 sind im Gesamtprotokoll dokumentiert.
- `evaluation-report.json`: alle acht ergänzenden Szenarien einschließlich Messrohwerten.
- `environment.txt`: erfasste System- und Toolchain-Angaben sowie Git-Status.
- `artifacts.tar.gz`: vollständige gesicherte Szenarioartefakte und Gesamtprotokoll.

Alle 19 E2E-Szenarien und acht ergänzenden Szenarien bestanden. Der Stabilitätstest
umfasste 100 Zyklen in 175 Sekunden; der Race-Test 5387 Deskriptorwechsel ohne
beobachteten Fehlentzug. Die 17 Kernel-Log-Differenzen der isolierten Szenarien
enthielten keine Treffer für die vom Runner geprüften Kernel-Fehlermuster.

Die Berichte enthalten den geprüften Commit und die Rohdaten zur Nachprüfbarkeit.
PERF-03 verwendet die instrumentierte Messung mit überprüftem Ruhezustand,
vollständiger Bündelungsphase und Zeitmarkierungen um die Map-Aktivierung.
Die älteren Nachweise bleiben unverändert erhalten.
