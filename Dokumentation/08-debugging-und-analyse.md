# Debugging und Analyse

## Userspace-Logs

Das Hauptprogramm nutzt `env_logger`. Ohne `RUST_LOG` wird `info` verwendet.

```shell
RUST_LOG=info sudo -E ./target/release/tails-pdp
```

Mehr Details:

```shell
RUST_LOG=debug sudo -E ./target/release/tails-pdp
```

## Kernel-Debug-Logs

Kernel-Debug-Ausgaben über `bpf_printk!` sind standardmäßig deaktiviert. Aktivierung:

```shell
TAILS_PDP_EBPF_DEBUG=1 RUST_LOG=info sudo -E ./target/release/tails-pdp
```

In einem zweiten Terminal:

```shell
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

## Prüfen, ob Programme geladen sind

```shell
sudo bpftool prog show
```

Nach Namen filtern:

```shell
sudo bpftool prog show | grep tails
sudo bpftool prog show | grep file_open
sudo bpftool prog show | grep socket_bind
```

## Maps anzeigen

```shell
sudo bpftool map show
```

Gepinnte Maps:

```shell
ls -l /sys/fs/bpf/tails-pdp
```

Einzelne Map dumpen:

```shell
sudo bpftool map dump pinned /sys/fs/bpf/tails-pdp/POLICY_GENERATION
sudo bpftool map dump pinned /sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES
sudo bpftool map dump pinned /sys/fs/bpf/tails-pdp/SOCKET_BIND_STATIC_POLICIES
```

Lesbarer ist oft das Admin-Tool:

```shell
./target/release/tails-pdp-admintool show
./target/release/tails-pdp-admintool show-active
```

## Inode und Device einer Datei prüfen

Schnell:

```shell
ls -li /home/hntr/test.txt
```

Mit Device-Werten:

```shell
stat -c 'inode=%i dev_dec=%d dev_hex=%D path=%n' /home/hntr/test.txt
```

Major/Minor:

```shell
stat -c 'major=%t minor=%T inode=%i path=%n' /home/hntr/test.txt
```

Die Policy-Map speichert den Kernel-Device-Wert. Der Userspace-Code konvertiert mit:

```text
(major << 20) | minor
```

Diese Logik steht in `tails-pdp-common/src/lib.rs` und `tails-pdp/src/monitor.rs`.

## Socket-Bind testen

Einfach auf Port 8080 lauschen:

```shell
python3 -c "import socket, time; s=socket.socket(); s.bind(('0.0.0.0', 8080)); s.listen(1); print('listening'); time.sleep(300)"
```

Von einem anderen Rechner Daten senden:

```shell
nc <IP-DES-ZIELRECHNERS> 8080
```

Oder nur lokal testen:

```shell
python3 -c "import socket; s=socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.bind(('0.0.0.0', 8080)); print('bind ok')"
```

## `/proc` für den Monitor prüfen

Aktive TCP-Sockets:

```shell
cat /proc/net/tcp
cat /proc/net/tcp6
```

FDs eines Prozesses:

```shell
ls -l /proc/<PID>/fd
```

Prozessinformationen:

```shell
cat /proc/<PID>/status
```

## Verifier-Fehler untersuchen

Das Hauptprogramm setzt `VerifierLogLevel::VERBOSE | VerifierLogLevel::STATS` in
`tails-pdp/src/main.rs`. Dadurch sind Verifier-Logs bei Ladefehlern ausführlicher.

Typische Hinweise:

| Meldung | Bedeutung |
| --- | --- |
| `invalid access to map value` | Offset oder Größe eines Map-Zugriffs passt nicht. |
| `BPF program is too large` | Verifier hat zu viele Instruktionen oder Zustände verarbeitet. |
| `R0 has unknown scalar value` | Rückgabewert ist nicht ausreichend eingeschränkt. |
| `R1 type=fp expected=ptr_` | Falscher Pointer-Typ für Helper-Funktion. |

Bei solchen Fehlern helfen:

- eBPF-Programm in kleinere Tail-Call-Schritte teilen
- Struct-Layouts prüfen
- Stack-Nutzung reduzieren
- Map-Zugriffe defensiv machen
- keine komplexen Rust-Patterns im eBPF-Teil verwenden

## Stale Maps entfernen

Wenn sich Structs oder Map-Größen geändert haben:

```shell
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/FILE_OPEN_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/SOCKET_BIND_STATIC_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/SOCKET_BIND_STREAM_POLICIES
sudo rm -f /sys/fs/bpf/tails-pdp/POLICY_GENERATION
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME
sudo rm -f /sys/fs/bpf/tails-pdp/CURRENT_TIME_ISO8601
```

## Quellen dieses Kapitels

Dieses Kapitel stützt sich auf die Projektquellen [P1], [P4], [P6], [P8], [P12] und [P17] sowie
auf die externen Quellen [Q5], [Q7], [Q12], [Q13], [Q14], [Q16], [Q17], [Q22] und [Q23]. Die
vollständige Quellenliste steht in [Quellen und Zitierweise](12-quellen.md).
