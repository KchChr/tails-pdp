#!/usr/bin/env bash
# Sourced by demo.sh --worker. All scenario orchestration stays in Bash.

fail() { printf '\nFEHLER: %s\n' "$*" >&2; return 1; }
alive() {
    local state
    state="$(ps -o stat= -p "$runtime_pid")" || return 1
    [[ -n "$state" && "$state" != *Z* ]]
}
observe() { printf '%s\n' "$*" | tee -a "$demo_root/observer.log"; }
pause_demo() {
    if [[ "$DEMO_AUTO" == 0 ]]; then
        read -r -p 'Enter: ausführen | Strg+C: abbrechen ' _
    fi
}
chapter() {
    printf '\n\033[1;36m%s\033[0m\n%s\n\n' "$1" "$2"
    pause_demo
}
admin() {
    "$ADM_TOOL_BIN" --policy-dir "$policy_dir" --attributes-dir "$attribute_dir" "${1:-show-active}"
}
generations() {
    local output
    output="$(admin)" || return 1
    [[ "$output" =~ generation\ policy=([0-9]+).*attribute=([0-9]+) ]] || return 1
    printf '%s %s\n' "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}"
}
wait_log() {
    local pattern="$1" offset="${2:-0}" deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while (( SECONDS < deadline )); do
        alive || { fail 'Runtime wurde beendet; siehe Runtime-Log.'; return 1; }
        # Redirect to a file first: grep -q must not SIGPIPE tail under pipefail.
        tail -n "+$((offset + 1))" "$demo_root/runtime.log" > "$demo_root/log-slice"
        if grep -Fq -- "$pattern" "$demo_root/log-slice"; then return 0; fi
        sleep 0.1
    done
    fail "Timeout bei Logmeldung: $pattern"
}
wait_generation() {
    local kind="$1" before="$2" offset="$3" current deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    local policy attribute
    while (( SECONDS < deadline )); do
        alive || { fail 'Runtime wurde beendet.'; return 1; }
        if current="$(generations)"; then
            read -r policy attribute <<< "$current"
            if { [[ "$kind" == policy && "$policy" != "$before" ]]; } ||
               { [[ "$kind" == attribute && "$attribute" != "$before" ]]; }; then
                wait_log "scan completed policy_generation=$policy attribute_generation=$attribute" "$offset"
                observe "Aktiviert: Policygeneration $policy, Attributgeneration $attribute; FD-Prüfung abgeschlossen."
                return 0
            fi
        fi
        sleep 0.1
    done
    fail "Timeout beim Aktivieren von $kind."
}
publish() {
    local destination="$1"
    cat > "$demo_root/prepared"
    printf '\nVeröffentliche %s:\n' "${destination#"$demo_root/"}"
    cat "$demo_root/prepared"
    bash "$PROJECT_ROOT/scripts/publish-config.sh" "$demo_root/prepared" "$destination"
}
policy() {
    local name="$1" effect="$2" conditions="${3:-}" command="${4:-}" before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    {
        printf 'policy "%s"\n%s\n    action == "file_open";\n    resource.path == "%s";\n' "$name" "$effect" "$target"
        [[ -z "$command" ]] || printf '    command == "%s";\n' "$command"
        printf '%s\n' "$conditions"
    } | publish "$policy_dir/$name.policy"
    wait_generation policy "${before%% *}" "$offset"
}
attribute() {
    local relative="$1" text="$2" before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    printf '%s\n' "$text" | publish "$attribute_dir/$relative"
    wait_generation attribute "${before##* }" "$offset"
}
remove_policy() {
    local name="$1" before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    printf '\nEntferne Policy %s\n' "$name"
    rm -- "$policy_dir/$name.policy"
    wait_generation policy "${before%% *}" "$offset"
}
access_is() {
    local expected="$1" command="${2:-tails-demo}" uid="${3:--}" file="${4:-$target}" actual
    alive || { fail 'Runtime beendet.'; return 1; }
    actual="$(python3 "$PROJECT_ROOT/scripts/demo/probe.py" access "$file" "$command" "$uid")"
    [[ "$actual" == "$expected" ]] || { fail "Zugriff: erwartet $expected, beobachtet $actual ($command, UID $uid)."; return 1; }
    observe "OK: Zugriff $actual (comm=$command, Real-UID=$uid, Datei=${file##*/})."
}
probe_state_is() {
    kill -0 "$probe_pid" 2>/dev/null || return 1
    python3 - "$probe_dir/state.json" "$1" <<'PY'
import json, sys
from pathlib import Path
path = Path(sys.argv[1])
if not path.exists():
    raise SystemExit(1)
state = json.loads(path.read_text())
expected = sys.argv[2] == 'open'
raise SystemExit(0 if state['protected'] == [expected] * 3 and state['controls'] == [True] * 2 else 1)
PY
}
start_probe() {
    probe_dir="$(mktemp -d "$demo_root/fd.XXXXXX")"
    python3 "$PROJECT_ROOT/scripts/demo/probe.py" hold "$target" "$safe" "$probe_dir" >> "$demo_root/observer.log" 2>&1 &
    probe_pid=$!
    local deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while ! probe_state_is open; do
        kill -0 "$probe_pid" 2>/dev/null || { fail 'FD-Beobachter konnte Dateien nicht öffnen.'; return 1; }
        (( SECONDS < deadline )) || { fail 'Timeout beim Start des FD-Beobachters.'; return 1; }
        sleep 0.1
    done
}
stop_probe() {
    if [[ -n "$probe_pid" ]]; then
        kill -TERM "$probe_pid" 2>/dev/null || true
        wait "$probe_pid" 2>/dev/null || true
        probe_pid=''
    fi
}
expect_revoked() {
    local deadline=$((SECONDS + DEMO_TIMEOUT_SECONDS))
    while ! probe_state_is closed; do
        alive || { fail 'Runtime während des FD-Entzugs beendet.'; return 1; }
        kill -0 "$probe_pid" 2>/dev/null || { fail 'FD-Beobachter unerwartet beendet.'; return 1; }
        (( SECONDS < deadline )) || { fail 'FD-Entzug ausgeblieben oder Kontroll-FD geschlossen.'; return 1; }
        sleep 0.1
    done
    observe 'OK: Drei geschützte FDs entzogen, beide Kontroll-FDs offen, Hilfsprozess läuft weiter.'
}
assert_probe_identity() {
    python3 - "$probe_dir/ready.json" "$target" "$safe" <<'PY'
import json, os, sys
state = json.load(open(sys.argv[1]))
for key, path in [('protected', sys.argv[2]), ('controls', sys.argv[3])]:
    expected = os.stat(path)
    for fd in state[key]:
        actual = os.stat(f'/proc/{state["pid"]}/fd/{fd}')
        if (actual.st_dev, actual.st_ino) != (expected.st_dev, expected.st_ino):
            raise SystemExit('FD-Identität stimmt vor dem Auslöser nicht überein')
PY
}

setup_demo_bpffs() {
    local current_namespace mount_point="${1:-/sys/fs/bpf}"
    current_namespace="$(readlink /proc/self/ns/mnt)" || return 1
    if [[ -z "${DEMO_PARENT_MOUNT_NS:-}" || "$current_namespace" == "$DEMO_PARENT_MOUNT_NS" ]]; then
        fail 'Privater Mount-Namespace fehlt; kein Mount im ursprünglichen Namespace.'
        return 1
    fi
    [[ -d "$mount_point" ]] || { fail "Mountpunkt $mount_point fehlt."; return 1; }
    mount -t bpf -o mode=700 bpf "$mount_point" || {
        fail 'Eigenes Demo-bpffs konnte nicht eingehängt werden.'; return 1;
    }
    [[ "$(stat -f -c %T "$mount_point")" == bpf_fs ]] || { fail 'Demo-Mount ist kein bpffs.'; return 1; }
}

stop_runtime() {
    [[ -n "$runtime_pid" ]] || return 0
    kill -TERM "$runtime_pid" 2>/dev/null || true
    local deadline=$((SECONDS + 5))
    while alive && (( SECONDS < deadline )); do sleep 0.1; done
    if alive; then kill -KILL "$runtime_pid" 2>/dev/null || true; fi
    wait "$runtime_pid" 2>/dev/null || true
    runtime_pid=''
}
worker_cleanup() {
    local status=$? name
    trap - EXIT INT TERM HUP
    set +e
    stop_probe
    stop_runtime
    if [[ "$owns_pins" == 1 ]]; then
        for name in POLICY_GENERATION ATTRIBUTE_GENERATION FILE_OPEN_STATIC_POLICIES FILE_OPEN_STREAM_POLICIES CURRENT_TIME ATTRIBUTES; do
            rm -f -- "$pin_dir/$name" || status=1
        done
    fi
    printf '%s\n' "$status" > "$demo_root/exit-status"
    chown -R "$DEMO_CALLER_UID:$DEMO_CALLER_GID" "$demo_root"
    if (( status == 0 )); then
        printf '\nDemo erfolgreich. Runtime und Hilfsprozesse beendet; eigene Maps entfernt.\n'
    else
        printf '\nDemo abgebrochen (Status %s). Diagnose: %s\n' "$status" "$demo_root"
    fi
    # Keep the result readable, including on an assertion failure. On HUP/TERM
    # there is no UI left to hold open.
    if [[ "$DEMO_AUTO" == 0 && "$status" -ne 130 && "$status" -ne 143 && -t 0 ]]; then
        read -r -p 'Enter: tmux-Demo schließen ' _ || true
    fi
    exit "$status"
}

demo_worker() {
    demo_root="$1"
    policy_dir="$demo_root/policies"
    attribute_dir="$demo_root/attributes"
    target="$demo_root/protected.txt"
    safe="$demo_root/control.txt"
    pin_dir=/sys/fs/bpf/tails-pdp
    runtime_pid='' probe_pid='' owns_pins=0
    exec > >(tee -a "$demo_root/transcript.log") 2>&1
    trap worker_cleanup EXIT
    trap 'exit 130' INT
    trap 'exit 143' TERM HUP

    [[ "$(uname -m)" == x86_64 ]] || { fail 'Der ptrace-basierte FD-Entzug benötigt x86_64-Linux.'; return 1; }
    [[ -r /sys/kernel/btf/vmlinux ]] || { fail 'Kernel-BTF fehlt.'; return 1; }
    [[ -r /sys/kernel/security/lsm ]] && grep -qw bpf /sys/kernel/security/lsm || {
        fail 'BPF-LSM ist nicht aktiv bzw. seine Konfiguration nicht lesbar.'; return 1;
    }
    mkdir -p /run/lock
    exec 9>/run/lock/tails-pdp-evaluation.lock
    flock -n 9 || { fail 'Eine Evaluation oder Demo läuft bereits.'; return 1; }
    if pgrep -x tails-pdp >/dev/null; then fail 'Es läuft bereits eine tails-pdp-Runtime.'; return 1; fi
    setup_demo_bpffs
    owns_pins=1
    mkdir -p "$policy_dir" "$attribute_dir/subjects" "$attribute_dir/resources"
    printf 'Geschützter Demo-Inhalt\n' > "$target"
    printf 'Weiterhin zulässiger Kontroll-Inhalt\n' > "$safe"
    ln -- "$target" "$demo_root/alias.txt"
    printf 'defcon = 5\n' > "$attribute_dir/system.attributes"
    cd "$demo_root"

    printf 'tails-pdp – geführte Live-Demo\nLogs: %s\n' "$demo_root"
    printf 'Eigener bpffs-Mount: vorhandene Host-Pins bleiben unverändert.\n'
    printf 'Links: Erklärung und Aktionen. Rechts oben: Runtime. Rechts unten: FD-Beobachter.\n'
    printf 'Nur die Enter-Taste ist für die Schritte nötig. Strg+C beendet die Demo.\n'
    chapter '1. Runtime starten und Ausgangszustand prüfen' \
        'Erwartung: Der BPF-LSM-Hook wird angehängt. Ohne Deny-Policy ist der Zugriff erlaubt.'
    RUST_LOG=info TAILS_PDP_EBPF_DEBUG=0 TAILS_PDP_TIMING=0 "$TAILS_PDP_BIN" > "$demo_root/runtime.log" 2>&1 &
    runtime_pid=$!
    wait_log 'Waiting for Ctrl-C'
    local name
    for name in POLICY_GENERATION ATTRIBUTE_GENERATION FILE_OPEN_STATIC_POLICIES FILE_OPEN_STREAM_POLICIES CURRENT_TIME ATTRIBUTES; do
        [[ -e "$pin_dir/$name" ]] || { fail "Map fehlt: $name"; return 1; }
    done
    wait_log 'scan completed'
    admin
    access_is allow

    chapter '2. Statische Regeln: Kommando, Benutzer und Ressource' \
        'Eine Deny-Regel gilt nur für comm=cat, Real-UID 60001 und die geschützte Datei. Andere Kombinationen bleiben erlaubt. Die Probe setzt den Linux-Tasknamen kontrolliert; sie führt dieselbe open-Operation aus.'
    policy scoped deny '    subject.uid == 60001;' cat
    access_is deny cat 60001
    access_is allow cat 60002
    access_is allow other 60001
    access_is allow cat 60001 "$safe"
    printf '\nEin Hardlink hat denselben Geräte-/Inode-Schlüssel: Auch der alternative Pfad wird verweigert.\n'
    access_is deny cat 60001 "$demo_root/alias.txt"
    admin show-policies
    remove_policy scoped
    access_is allow cat 60001

    chapter '3. Permit, Deny-Vorrang und Policy-Lebenszyklus' \
        'Erst Permit: Zugriff erlaubt. Zusätzlich Deny: Zugriff verweigert. Nach dem Entfernen der Deny-Regel ist der Zugriff wieder erlaubt. Kein Runtime-Neustart.'
    policy permit permit
    access_is allow
    policy deny deny
    access_is deny
    admin
    remove_policy deny
    access_is allow
    remove_policy permit

    chapter '4. Dynamisches Systemattribut' \
        'Die Deny-Regel trifft bei DEFCON <= 2 zu. Nur der Attributwert wechselt 5 → 2 → 5; die Policy bleibt gleich.'
    policy context deny '    system.defcon <= 2;'
    access_is allow
    attribute system.attributes 'defcon = 2'
    access_is deny
    admin show-attributes
    attribute system.attributes 'defcon = 5'
    access_is allow
    remove_policy context

    chapter '5. Subject-/Resource-Attribute und UND-Verknüpfung' \
        'Deny erfordert gleichzeitig DEFCON <= 2, Rolle engineer und Klassifikation internal. Jede einzelne Änderung kann die Regel unzutreffend machen.'
    attribute system.attributes 'defcon = 2'
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "internal"'
    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
    access_is deny
    attribute subjects/0.attributes 'position = "intern"'
    access_is allow
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "public"'
    access_is allow
    attribute "resources${target}.attributes" 'classification = "internal"'
    access_is deny
    printf '\nEin fehlendes oder anders typisiertes Rollenattribut erfüllt die String-Bedingung ebenfalls nicht.\n'
    attribute subjects/0.attributes '# position fehlt'
    access_is allow
    attribute subjects/0.attributes 'position = 1'
    access_is allow
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    admin
    remove_policy combined

    chapter '6. Ungültige Updates und anschließende Korrektur' \
        'Eine defekte Policy und DEFCON=9 werden zurückgewiesen. Generationen und wirksames Deny bleiben erhalten. Danach werden gültige Korrekturen ohne Neustart übernommen.'
    policy robust deny '    system.defcon <= 2;'
    local before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    printf 'policy "kaputt"\ndeny\n action == "file_open"\n' | publish "$policy_dir/broken.policy"
    wait_log 'POLICY sync failed' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültige Policy änderte die Generation.'; return 1; }
    access_is deny
    policy broken permit
    access_is deny
    remove_policy broken
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    printf 'defcon = 9\n' | publish "$attribute_dir/system.attributes"
    wait_log 'Ignoring invalid stream attributes' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültiges Attribut änderte die Generation.'; return 1; }
    access_is deny
    attribute system.attributes 'defcon = 5'
    access_is allow
    remove_policy robust

    chapter '7. Bereits geöffnete FDs durch eine neue Policy entziehen' \
        'Der Beobachter öffnet drei geschützte und zwei Kontroll-FDs. Danach wird eine Deny-Policy aktiviert: Nur die drei geschützten FDs werden geschlossen; der Prozess läuft weiter.'
    start_probe
    chapter '7a. FDs sind offen – jetzt Deny veröffentlichen' \
        'Der FD-Beobachter rechts unten zeigt den Ausgangszustand. Enter veröffentlicht die neue Regel.'
    assert_probe_identity
    policy revoke deny '' tails-demo-fd
    expect_revoked
    stop_probe
    remove_policy revoke

    chapter '8. FD-Entzug ausschließlich durch Attributänderung' \
        'Bei DEFCON=5 bleibt die vorhandene Regel inaktiv. Ein neuer Beobachter öffnet seine Dateien; anschließend wird nur DEFCON auf 2 gesetzt.'
    policy revoke deny '    system.defcon <= 2;' tails-demo-fd
    start_probe
    chapter '8a. Nur das Systemattribut ändern' \
        'Erwartung: Attributgeneration steigt, Policygeneration bleibt gleich, geschützte FDs werden entzogen.'
    assert_probe_identity
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    attribute system.attributes 'defcon = 2'
    local current
    current="$(generations)"
    [[ "${before%% *}" == "${current%% *}" ]] || { fail 'Policygeneration unerwartet geändert.'; return 1; }
    wait_log "scan started cause=[attributes:${current##* }]" "$offset"
    expect_revoked
    stop_probe
    remove_policy revoke

    chapter '9. FD-Entzug ausschließlich durch eine Zeitgrenze' \
        'Nach Enter wird eine Deny-Regel mit einer Zeitgrenze 12 Sekunden in der Zukunft vorbereitet. Der Beobachter öffnet davor seine Dateien. Danach ändern wir keine Konfiguration und verstellen keine Uhr.'
    local boundary
    boundary=$(( $(date +%s) + 12 ))
    (( boundary < 4294967296 )) || { fail 'Zeitgrenze außerhalb des Demo-Modulus.'; return 1; }
    policy timed deny "    environment.time % 4294967296 >= $boundary;" tails-demo-fd
    start_probe
    assert_probe_identity
    (( $(date +%s) < boundary - 2 )) || { fail 'Einrichtung zu langsam: Zeitgrenze schon zu nah.'; return 1; }
    access_is allow tails-demo-fd
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    observe "Warte auf Unix-Zeit $boundary. Keine Veröffentlichung und kein Neustart."
    wait_log "scan started cause=[time:$boundary]" "$offset"
    wait_log "scan completed policy_generation=${before%% *} attribute_generation=${before##* }" "$offset"
    expect_revoked
    [[ "$(generations)" == "$before" ]] || { fail 'Konfigurationsgeneration an Zeitgrenze verändert.'; return 1; }
    python3 - "$probe_dir/state.json" "$boundary" <<'PY'
import json, sys
state = json.load(open(sys.argv[1]))
if state['unix_ns'] < int(sys.argv[2]) * 1_000_000_000:
    raise SystemExit('FDs vor der Zeitgrenze geschlossen')
PY
    access_is deny tails-demo-fd
    stop_probe
    remove_policy timed
    access_is allow tails-demo-fd

    chapter '10. UTC-Zeitbedingung und abschließende Inspektion' \
        'Zusätzlich zur Modulo-Zeitbedingung zeigen wir einen UTC-Stundenvergleich. Eine tautologisch zutreffende Grenze (Stunde >= 0) macht die Demo unabhängig von der Tageszeit.'
    policy utc deny '    environment.utc.hour >= 0;'
    access_is deny
    policy stream-permit permit '    environment.utc.minute >= 0;'
    access_is deny
    admin
    remove_policy utc
    access_is allow
    remove_policy stream-permit
    observe 'Alle Demo-Kapitel erfolgreich geprüft.'
    printf '\nGrenzen: FD-Schließen holt gelesene Daten nicht zurück; mmap und ptrace-Races sind nicht durch diese Demo abgedeckt.\n'
}
