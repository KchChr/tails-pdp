#!/usr/bin/env bash
# Sourced by demo.sh --isolated-worker. The commented demo chapters are in
# demo_worker below; helpers implement publication, observation and assertions.

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
    printf '\n\033[1;36m%s\033[0m\n' "$1"
    printf '\nAusgangslage:\n  %s\n' "$2"
    printf '\nAktion:\n  %s\n' "$3"
    printf '\nErwartetes Verhalten:\n  %s\n' "$4"
    printf '\nDarauf achten:\n  %s\n\n' "$5"
    pause_demo
}
explain() { printf '\n→ %s\n' "$*"; }
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
    printf 'allow = Dateiöffnung erlaubt; deny = vom LSM mit EPERM verweigert. Andere Fehler brechen die Demo ab.\n'
    printf 'Die Policygeneration zählt aktivierte Regelstände; die Attributgeneration zählt aktivierte Attributstände.\n'
    printf 'show-active zeigt geladene Regeln und Werte. Ob ein Zugriff erlaubt ist, prüfen wir zusätzlich mit einer echten Dateiöffnung.\n'

    # Kapitel 1: Die Durchsetzung erst nach dem nachgewiesenen LSM-Attach prüfen.
    # Der leere Regelbestand zeigt das Allow-Verhalten ohne passende Deny-Regel.
    chapter '1. Runtime starten und Ausgangszustand prüfen' \
        'Die Demo-Dateien sind vorbereitet. Es läuft noch keine Demo-Runtime und es sind keine Policies geladen.' \
        'Wir starten tails-pdp. Es lädt das eBPF-Programm, bereitet die Maps vor und hängt den file_open-Hook an. Danach öffnen wir die geschützte Datei.' \
        'Alle erwarteten Maps existieren, die Runtime läuft und die Dateiöffnung ist erlaubt: Ohne passende Deny-Regel wird kein Zugriff untersagt.' \
        'Rechts oben bestätigt die Runtime ihren Start. Links zeigt das Admin-Tool den geladenen Zustand; die anschließende OK-Zeile bestätigt den tatsächlichen Zugriff.'
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
    explain 'Ergebnis: Die Runtime ist bereit und der Ausgangszugriff ist erlaubt. Ab jetzt bleibt derselbe Runtime-Prozess aktiv.'

    # Kapitel 2: Pro Negativkontrolle genau einen Filter verändern. Der Hardlink
    # belegt zusätzlich, dass die Ressourcenidentität und nicht der Pfad zählt.
    chapter '2. Statische Regeln: Kommando, Benutzer und Ressource' \
        'Die geschützte Datei und eine separate Kontrolldatei sind zugänglich. Ein Hardlink verweist unter einem anderen Namen auf dieselbe geschützte Datei.' \
        'Wir veröffentlichen eine Deny-Regel für genau drei gemeinsam erforderliche Merkmale: Real-UID 60001, Linux-Taskname cat und die geschützte Ressource. Danach variieren wir diese Merkmale einzeln.' \
        'Nur die passende Kombination wird verweigert. Eine andere UID, ein anderer Taskname und die Kontrolldatei bleiben erlaubt. Der Hardlink wird ebenfalls verweigert, weil Gerät und Inode gleich sind.' \
        'Die Zugriffshilfe setzt den Tasknamen gezielt; sie startet kein echtes cat. Für den UID-Vergleich ändert sie nur die Real-UID, die effektive UID bleibt root. Es werden keine Benutzerkonten angelegt.'
    policy scoped deny '    subject.uid == 60001;' cat
    explain 'Alle drei Filter passen: Die Dateiöffnung muss verweigert werden.'
    access_is deny cat 60001
    explain 'Negativkontrollen: jeweils eine andere UID, ein anderer Taskname oder eine andere Datei. Diese Zugriffe müssen erlaubt bleiben.'
    access_is allow cat 60002
    access_is allow other 60001
    access_is allow cat 60001 "$safe"
    explain 'Der alternative Hardlink-Pfad bezeichnet dieselbe Datei. Die Sperre gilt auch dort.'
    access_is deny cat 60001 "$demo_root/alias.txt"
    admin show-policies
    explain 'Wir entfernen die Regel. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    access_is allow cat 60001

    # Kapitel 3: Permit hebt ein gleichzeitig passendes Deny nicht auf.
    # Jede Veröffentlichung/Entfernung aktiviert einen neuen vollständigen Stand.
    chapter '3. Permit, Deny-Vorrang und Policy-Lebenszyklus' \
        'Nach dem Entfernen der vorherigen Regel ist der Regelbestand wieder leer. Wir verwenden nun keine Benutzer- oder Kommandofilter.' \
        'Wir laden zuerst Permit, ergänzen eine passende Deny-Regel und entfernen anschließend nur Deny. Zum Schluss entfernen wir auch Permit.' \
        'Die Zugriffe folgen der Reihenfolge erlaubt → verweigert → erlaubt. Bei gleichzeitig passenden Regeln hat Deny Vorrang vor Permit.' \
        'Die Policygeneration ändert sich bei den Veröffentlichungen und Entfernungen. Neue Entscheidungen werden ohne Neustart wirksam. Die Reihenfolge der Dateinamen bestimmt keine Priorität.'
    explain 'Nur Permit ist vorhanden: Der Zugriff ist erlaubt.'
    policy permit permit
    access_is allow
    explain 'Jetzt treffen Permit und Deny gleichzeitig zu: Deny setzt sich durch.'
    policy deny deny
    access_is deny
    admin
    explain 'Nur Deny wird entfernt; Permit bleibt geladen. Der Zugriff ist wieder erlaubt.'
    remove_policy deny
    access_is allow
    remove_policy permit

    # Kapitel 4: Bei unveränderter Policy die Entscheidung allein über einen
    # Systemattributwert ändern; Attribut- und Policygeneration sind getrennt.
    chapter '4. Dynamisches Systemattribut' \
        'Das globale Attribut system.defcon steht auf 5. Diese Zahl dient als dynamischer Kontext der Zugriffsentscheidung.' \
        'Wir laden eine Deny-Regel mit system.defcon <= 2 und ändern anschließend nur den Attributwert von 5 auf 2 und zurück auf 5.' \
        'Bei 5 ist die Deny-Bedingung falsch und der Zugriff erlaubt. Bei 2 ist sie erfüllt und der Zugriff verweigert. Nach der Rückkehr zu 5 ist er wieder erlaubt.' \
        'Die Regeldatei bleibt während der Attributwechsel gleich. Im Log und im Admin-Tool ändert sich der Attributstand; die Runtime muss dafür nicht neu gestartet werden.'
    policy context deny '    system.defcon <= 2;'
    access_is allow
    explain 'DEFCON sinkt auf 2: Die bereits geladene Deny-Regel trifft jetzt zu.'
    attribute system.attributes 'defcon = 2'
    access_is deny
    admin show-attributes
    explain 'DEFCON steigt wieder auf 5: Dieselbe Regel trifft nicht mehr zu.'
    attribute system.attributes 'defcon = 5'
    access_is allow
    remove_policy context

    # Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
    # Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
    # das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
    chapter '5. Subject-/Resource-Attribute und UND-Verknüpfung' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff läuft mit Real-UID 0.' \
        'Wir setzen DEFCON=2, die Rolle von UID 0 auf engineer und die Dateiklassifikation auf internal. Eine Deny-Regel verknüpft alle drei Bedingungen mit UND. Danach ändern wir einzelne Werte.' \
        'Deny gilt nur, wenn alle drei Bedingungen erfüllt sind. Rolle intern oder Klassifikation public reichen jeweils aus, damit diese Deny-Regel nicht mehr passt.' \
        'Anschließend prüfen wir eine fehlende Rolle und die Zahl 1 statt eines Rollenstrings. Beide Attributstände sind gültig, erfüllen aber den Vergleich mit "engineer" nicht. Deshalb greift hier kein Deny.'
    attribute system.attributes 'defcon = 2'
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "internal"'
    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
    access_is deny
    explain 'Nur die Rolle wird engineer → intern geändert. Damit ist eine der drei UND-Bedingungen falsch.'
    attribute subjects/0.attributes 'position = "intern"'
    access_is allow
    attribute subjects/0.attributes 'position = "engineer"'
    explain 'Die Rolle stimmt wieder. Jetzt ändern wir nur die Dateiklassifikation internal → public.'
    attribute "resources${target}.attributes" 'classification = "public"'
    access_is allow
    explain 'Mit classification=internal sind wieder alle drei Bedingungen erfüllt.'
    attribute "resources${target}.attributes" 'classification = "internal"'
    access_is deny
    explain 'Jetzt fehlt position vollständig. Die Veröffentlichung ist gültig, der Rollenvergleich ergibt aber keinen Treffer.'
    attribute subjects/0.attributes '# position fehlt'
    access_is allow
    explain 'position=1 ist eine Zahl. Ein Zahlenwert erfüllt den Stringvergleich mit "engineer" ebenfalls nicht.'
    attribute subjects/0.attributes 'position = 1'
    access_is allow
    explain 'Wir stellen den Rollenstring engineer wieder her: Alle Bedingungen passen und der Zugriff wird verweigert.'
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    admin
    remove_policy combined

    # Kapitel 6: Syntax-/Validierungsfehler dürfen keine neue Generation
    # aktivieren. Nach der Ablehnung muss eine gültige Korrektur weiter möglich sein.
    chapter '6. Ungültige Updates und anschließende Korrektur' \
        'DEFCON steht noch auf 2. Wir laden eine passende Deny-Regel und merken uns vor jedem fehlerhaften Update beide Generationsnummern.' \
        'Zuerst veröffentlichen wir eine Policy mit fehlendem Semikolon. Nach ihrer Korrektur veröffentlichen wir DEFCON=9, obwohl für dieses Attribut nur 1 bis 5 zulässig sind.' \
        'Beide fehlerhaften Updates werden verworfen. Die zuletzt gültigen Generationen und das wirksame Deny bleiben erhalten. Gültige Korrekturen werden anschließend wieder übernommen.' \
        'Rechts oben erscheint die Ablehnung. Links prüfen wir die unveränderten Generationen und den weiterhin verweigerten Zugriff. Das ist keine Rückkehr zu einem leeren Regelbestand.'
    policy robust deny '    system.defcon <= 2;'
    local before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    explain 'Die nächste Policy ist absichtlich syntaktisch fehlerhaft. Sie darf nicht aktiviert werden.'
    printf 'policy "kaputt"\ndeny\n action == "file_open"\n' | publish "$policy_dir/broken.policy"
    wait_log 'POLICY sync failed' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültige Policy änderte die Generation.'; return 1; }
    access_is deny
    explain 'Wir ersetzen die fehlerhafte Datei durch eine gültige Permit-Policy. Das bereits vorhandene Deny hat weiterhin Vorrang.'
    policy broken permit
    access_is deny
    remove_policy broken
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    explain 'DEFCON=9 ist unzulässig. Der aktive Wert muss trotz geänderter Quelldatei bei 2 bleiben.'
    printf 'defcon = 9\n' | publish "$attribute_dir/system.attributes"
    wait_log 'Ignoring invalid stream attributes' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültiges Attribut änderte die Generation.'; return 1; }
    access_is deny
    explain 'Mit dem gültigen Wert 5 wird ein neuer Attributstand aktiviert. Die Deny-Bedingung ist danach falsch und der Zugriff wieder erlaubt.'
    attribute system.attributes 'defcon = 5'
    access_is allow
    remove_policy robust

    # Kapitel 7: file_open schützt neue Öffnungen. Der Userspace-PEP muss
    # zusätzlich bestehende FDs selektiv entziehen, ohne den Prozess zu beenden.
    chapter '7. Bereits geöffnete FDs durch eine neue Policy entziehen' \
        'Bisher haben wir neue Dateiöffnungen geprüft. Ein Prozess kann eine Datei aber schon geöffnet haben, bevor eine neue Regel veröffentlicht wird.' \
        'Wir starten einen Beobachter mit drei offenen FDs zur geschützten Datei und zwei offenen FDs zur Kontrolldatei. Erst im nächsten Schritt veröffentlichen wir eine passende Deny-Regel.' \
        'Zunächst müssen alle fünf FDs offen sein. Nach der Policyaktivierung prüft der Userspace-PEP bestehende FDs erneut und entzieht ausschließlich die drei geschützten.' \
        'FD bedeutet Dateideskriptor: eine offene Dateireferenz in einem Prozess. Rechts unten zeigt True einen offenen FD und False einen geschlossenen. Der Beobachterprozess soll weiterlaufen.'
    start_probe
    chapter '7a. FDs sind offen – jetzt Deny veröffentlichen' \
        'Der Beobachter hält alle fünf FDs offen. Wir prüfen vor der Änderung zusätzlich, dass diese FDs noch auf die erwarteten Dateien verweisen.' \
        'Enter veröffentlicht Deny für die geschützte Datei und den Tasknamen tails-demo-fd. Die Policyaktivierung löst eine erneute FD-Prüfung aus.' \
        'Die drei geschützten FDs wechseln auf False. Beide Kontroll-FDs bleiben True; der Prozess wird nicht beendet.' \
        'Rechts oben ist die Policyaktivierung mit anschließendem Scan sichtbar. Rechts unten ist der tatsächliche FD-Zustand zu sehen. Ein Logeintrag allein genügt nicht als Nachweis.'
    assert_probe_identity
    policy revoke deny '' tails-demo-fd
    expect_revoked
    explain 'Der selektive Entzug ist bestätigt. Wir beenden jetzt den Beobachter gezielt und entfernen die Demo-Regel für das nächste Kapitel.'
    stop_probe
    remove_policy revoke

    # Kapitel 8: Deny ist bereits geladen, seine Bedingung aber zunächst falsch.
    # Nur die Attributgeneration darf sich durch den Auslöser ändern.
    chapter '8. FD-Entzug ausschließlich durch Attributänderung' \
        'DEFCON steht auf 5. Wir installieren vor dem Öffnen eine Deny-Regel mit system.defcon <= 2. Die Regel ist aktiviert, ihre Bedingung ist jedoch noch nicht erfüllt.' \
        'Ein neuer Beobachter öffnet drei geschützte und zwei Kontroll-FDs. Danach ändern wir im nächsten Schritt ausschließlich das Systemattribut.' \
        'Solange DEFCON=5 gilt, bleiben alle FDs offen. Der spätere Wechsel auf 2 muss den Entzug ohne Änderung der Policydatei auslösen.' \
        'Hier unterscheiden wir eine geladene Regel von einer erfüllten Bedingung. enabled im Admin-Tool bedeutet nicht, dass die Regel auf jeden Zugriff zutrifft.'
    policy revoke deny '    system.defcon <= 2;' tails-demo-fd
    start_probe
    chapter '8a. Nur das Systemattribut ändern' \
        'Die Regel ist bereits geladen und der Beobachter hält seine FDs offen. Wir merken uns die aktuelle Policygeneration.' \
        'Enter veröffentlicht ausschließlich DEFCON=2. Der Attributloader aktiviert den neuen Wert und löst damit eine FD-Prüfung aus.' \
        'Die Attributgeneration steigt, die Policygeneration bleibt gleich. Nur die drei geschützten FDs werden geschlossen; beide Kontroll-FDs bleiben offen.' \
        'Rechts oben verlangt die Demo einen Scan mit Ursache attributes:<Generation>. Damit zeigen wir den Attributwechsel als Auslöser und nicht eine zusätzlich veröffentlichte Policy.'
    assert_probe_identity
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    attribute system.attributes 'defcon = 2'
    local current
    current="$(generations)"
    [[ "${before%% *}" == "${current%% *}" ]] || { fail 'Policygeneration unerwartet geändert.'; return 1; }
    wait_log "scan started cause=[attributes:${current##* }]" "$offset"
    expect_revoked
    explain 'Die unveränderte Policygeneration und der attributes-Auslöser sind geprüft. Die Kontextänderung allein hat die bestehenden Zugriffe entzogen.'
    stop_probe
    remove_policy revoke

    # Kapitel 9: Erst nach der Enter-Pause die Grenze berechnen. Ab dem Öffnen
    # nichts mehr veröffentlichen; Zeit-Trigger und konstante Generationen prüfen.
    chapter '9. FD-Entzug ausschließlich durch eine Zeitgrenze' \
        'Eine Zeitbedingung kann ihren Wahrheitswert ändern, ohne dass jemand eine Policy oder ein Attribut veröffentlicht.' \
        'Nach Enter berechnen wir eine Grenze zwölf Sekunden in der Zukunft, laden die Zeitregel und öffnen die Dateien davor. Anschließend warten wir ohne weitere Konfigurationsänderung.' \
        'Vor der Grenze sind die FDs offen. Nach Erreichen der Grenze wird die Deny-Bedingung wahr und ein zeitgetriggerter Scan entzieht die drei geschützten FDs. Beide Konfigurationsgenerationen bleiben gleich.' \
        'Die Uhr wird nicht verstellt. Der große Modulus 4294967296 macht den Vergleich in der aktuellen Unix-Epoche zu einem einmaligen nahen Übergang. Im Log ist time:<Zeitgrenze> der Auslöser. Während dieser zwölf Sekunden gibt es keine weitere Enter-Pause.'
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
    explain 'Der Zeit-Auslöser, unveränderte Generationen und der FD-Entzug nach der Grenze sind bestätigt. Auch eine neue Dateiöffnung wird nun verweigert.'
    stop_probe
    remove_policy timed
    access_is allow tails-demo-fd

    # Kapitel 10: UTC-Felder ergänzen die Modulo-Demo. Immer wahre Vergleiche
    # vermeiden eine Abhängigkeit von der Vorführungszeit und zeigen Deny-Vorrang.
    chapter '10. UTC-Zeitbedingung und abschließende Inspektion' \
        'Neben Unix-Zeit mit Modulus unterstützt der Prototyp UTC-Zeitfelder. Der vorherige zeitabhängige Regelstand wurde entfernt.' \
        'Wir laden Deny für environment.utc.hour >= 0 und zusätzlich Permit für environment.utc.minute >= 0, inspizieren die aktiven Maps und entfernen danach nur Deny.' \
        'Beide Bedingungen sind zu jeder gültigen Tageszeit wahr. Mit beiden Regeln gilt Deny-Vorrang; nach dem Entfernen von Deny ist der Zugriff wieder erlaubt.' \
        'Die bewusst immer wahren Vergleiche zeigen die UTC-Felder unabhängig von der Uhrzeit der Vorführung. Das Admin-Tool zeigt die Regeln, die Zugriffshilfe prüft deren tatsächliche Wirkung.'
    policy utc deny '    environment.utc.hour >= 0;'
    access_is deny
    policy stream-permit permit '    environment.utc.minute >= 0;'
    explain 'Auch die zusätzliche zeitabhängige Permit-Regel hebt das passende Deny nicht auf.'
    access_is deny
    admin
    explain 'Wir entfernen nur die UTC-Deny-Regel. Das Stream-Permit bleibt zunächst geladen.'
    remove_policy utc
    access_is allow
    remove_policy stream-permit
    explain 'Alle Demo-Policies sind wieder entfernt. Beim Schließen werden Runtime und Hilfsprozesse beendet und die eigenen Maps aufgeräumt. Die Logs bleiben erhalten.'
    observe 'Alle Demo-Kapitel erfolgreich geprüft.'
    printf '\nGrenzen: FD-Schließen holt gelesene Daten nicht zurück; mmap und ptrace-Races sind nicht durch diese Demo abgedeckt.\n'
}
