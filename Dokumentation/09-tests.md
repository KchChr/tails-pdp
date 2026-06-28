# Tests und Teststrategie

## Aktueller Stand

Unit-Tests in [`tails-pdp-common/src/lib.rs`](../tails-pdp-common/src/lib.rs) prüfen vor allem
Stream-Policy-Semantik. Ergänzend besitzen Policyloader, Attributloader und Userspace-PEP eigene
komponentennahe Tests:

- Zeitbedingung wahr ergibt Entitlement.
- Zeitbedingung falsch ergibt `None`.
- Modulo `0` ergibt `None`.
- DEFCON-Bedingung wahr ergibt Entitlement.
- DEFCON-Bedingung falsch ergibt `None`.
- Freie Subjektattribute werden in Stream-Policy-Einträge übersetzt.
- Ungültige Attributnamen werden abgelehnt.
- Zahlen-, Bool- und Stringattribute werden korrekt geparst.
- Prozess- und FD-Namen aus `/proc` werden nur als Zahlen akzeptiert.

Diese Tests betreffen die gemeinsame Logik, die eBPF und Userspace-PEP verwenden [P6], [P8].

Ausführung ohne den globalen Cargo-Runner:

```shell
cargo test -p tails-pdp-common --config 'target."cfg(all())".runner="env"'
cargo test --target x86_64-unknown-linux-musl --no-run \
  -p tails-pdp-policy-loader \
  -p tails-pdp-attribute-loader \
  -p tails-pdp-userspace-pep
```

Der direkte `cargo test` kann durch `.cargo/config.toml` über `sudo -E` laufen. Für normale
Unit-Tests ist das unpraktisch.

## Sinnvolle Testebenen

### 1. Unit-Tests für `tails-pdp-common`

Diese Tests sind am wichtigsten, weil eBPF und Userspace dieselbe Logik nutzen.

Sinnvolle Fälle:

- `file_open` Static Deny bei passender UID, Command und Datei.
- `file_open` Static gibt `None`, wenn UID nicht passt.
- `file_open` Static gibt `None`, wenn Inode nicht passt.
- `ANY_SUBJECT` matcht jede UID.
- Stream `hour < 8` trifft vor 8 Uhr.
- Stream `hour >= 16` trifft ab 16 Uhr.
- Stream `defcon <= 2` trifft bei DEFCON 1 oder 2.
- Stream `defcon <= 2` trifft nicht bei DEFCON 3, 4 oder 5.
- Stream-Bedingung falsch erzeugt keine Gegenentscheidung.

Implementierung:

- Entweder im bestehenden `#[cfg(test)] mod tests`.
- Oder besser später in `tails-pdp-common/tests/policy_eval.rs`.

### 2. Parser-Tests für `.sapl`

Ziel: Prüfen, ob Policy-Dateien korrekt geparst, validiert und in kernelgeeignete Einträge übersetzt werden.

Sinnvolle Fälle:

- gültige `file_open` Static Policy
- gültige `file_open` Stream Policy
- gültige `system.defcon <= 2`
- ungültige DEFCON-Werte `0` und `6`
- doppelte Policy-Namen werden abgelehnt
- fehlendes Semikolon wird abgelehnt
- unbekannte Action wird abgelehnt
- mehr Bedingungen als das Map-Layout zulässt werden abgelehnt
- mehr Policies als `POLICY_BANK_SIZE` erlaubt werden abgelehnt

Implementierung:

- Parser-Funktionen testbar machen, ohne die öffentlichen APIs unnötig zu vergrößern.
- Temporäre Verzeichnisse nutzen, z. B. mit `tempfile`.
- `translate_policy_documents` und `parse_policy_document` testen.

### 3. Generationen- und Rollback-Tests

Ziel: Sicherstellen, dass kaputte Updates nicht aktiv werden.

Sinnvolle Fälle:

- Neue Generation wird erst nach erfolgreichem Schreiben aktiviert.
- Fehler beim Schreiben einer Map lässt alte Generation aktiv.
- Unveränderte Policies werden nicht erneut geschrieben.
- Ein bereits fehlgeschlagener Stand wird nicht jede Sekunde neu geschrieben.
- Entfernte Policy-Dateien werden in der nächsten Generation deaktiviert.

Implementierung:

- Map-Zugriffe hinter ein Trait legen, z. B. `PolicyMapWriter`.
- Produktiv nutzt das Trait Aya-Maps.
- Tests nutzen eine In-Memory-Fake-Map.

### 4. Userspace-PEP-Tests

Der Userspace-PEP ist aktuell stark an `/proc` gekoppelt. Für Tests sollte man Parsing und Auswertung
trennen.

Sinnvolle Fälle:

- Datei-FD wird zu `device + inode`.
- Verbotene Datei erzeugt Violation.
- Erlaubte Datei erzeugt keine Violation.
- Bei `tail` werden Datei-FD und Inotify-FD erkannt.
- Nicht verbotene FDs bleiben unberührt.

Implementierung:

- `read_process_fds` und FD-Schließen abstrahieren.
- Fake-`/proc`-Daten in Tests verwenden.
- FD-Schließen über ein Trait wie `FdCloser` simulieren.

### 5. Admin-Tool-Tests

Sinnvolle Fälle:

- `--help` und keine Argumente zeigen Hilfe.
- ungültige Eingabe zeigt Fehler und Usage.
- `show` formatiert Static- und Stream-Policies korrekt.
- `show-active` blendet deaktivierte Policies aus.
- `clear-all --action file-open` betrifft nur File-Open-Maps.
- `set-stream --attribute time --modulo 0` wird abgelehnt.
- `hour > 23` wird abgelehnt.
- `defcon` außerhalb `1..=5` wird abgelehnt.

Implementierung:

- CLI-Parsing isoliert testen.
- Output-Funktionen mit Beispiel-Policies testen.
- Map-Zugriff über Fake-Maps abstrahieren.

### 6. Privilegierte Integrationstests

Diese Tests laufen nur auf Linux mit Root.

Szenarien:

#### Datei öffnen verboten

```shell
echo test >/home/hntr/test.txt
cat > policies/99-file-open-static-deny-cat-test.sapl <<'EOF'
policy "deny cat on /home/hntr/test.txt for uid 1000"
deny
    action == "file_open";
    subject.uid == 1000;
    command == "cat";
    resource.path == "/home/hntr/test.txt";
EOF
sudo -E ./target/release/tails-pdp
cat /home/hntr/test.txt
```

Erwartung: `cat` bekommt `Operation not permitted`.

#### Socket-Bind verboten

```shell
cp examples/20-socket-bind-static-deny-8080-tcp.sapl policies/
python3 -c "import socket; s=socket.socket(); s.bind(('0.0.0.0', 8080))"
```

Erwartung: Bind schlägt fehl.

#### Stream-Policy

Eine Policy mit `environment.utc.hour < 8` oder `>= 16` aktivieren und mit aktueller UTC-Zeit
vergleichen.

#### DEFCON-Policy über system.attributes

```shell
cp examples/15-file-open-stream-deny-defcon-le-2.sapl policies/
printf 'defcon = 5\n' > attributes/system.attributes
cat /home/hntr/test.txt
printf 'defcon = 2\n' > attributes/system.attributes
cat /home/hntr/test.txt
```

Erwartung: Bei DEFCON `5` greift die Policy nicht. Bei DEFCON `2` greift sie [P19], [P23].

#### Userspace-PEP nachträglich

1. Prozess öffnet Datei oder bindet Socket.
2. Policy wird danach in [`policies/`](../policies/) kopiert.
3. Userspace-PEP erkennt Violation.
4. Falls Enforcement aktiv ist, wird der FD geschlossen.

## Empfehlung

Priorität:

1. `tails-pdp-common` stark testen.
2. Policy-Parser und Generationenlogik testen.
3. Userspace-PEP testbar machen.
4. Privilegierte Linux-Smoke-Tests automatisieren.

---

**Previous:** [Debugging und Analyse](08-debugging-und-analyse.md) | **Next:** [Offene Punkte und Einschränkungen](10-offene-punkte.md)
