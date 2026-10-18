#!/usr/bin/env bash
# Sourced by demo.sh --isolated-worker. The commented demo chapters are in
# demo_worker below; helpers implement publication, observation and assertions.

# Initialise before the worker redirects stdout through tee. Colour is a display
# concern only; raw admin polling and helper return values remain undecorated.
init_demo_colors() {
    color_reset='' color_heading='' color_section='' color_command=''
    color_output='' color_config='' color_success='' color_error='' color_prompt=''
    if [[ -t 1 && "${TERM:-dumb}" != dumb && -z "${NO_COLOR:-}" ]]; then
        color_reset=$'\033[0m'
        color_heading=$'\033[1;36m'
        color_section=$'\033[1m'
        color_command=$'\033[93m'
        color_output=$'\033[94m'
        color_config=$'\033[95m'
        color_success=$'\033[92m'
        color_error=$'\033[91m'
        color_prompt=$'\033[1;93m'
    fi
}
init_demo_colors

fail() { printf '\n%sFEHLER: %s%s\n' "$color_error" "$*" "$color_reset" >&2; return 1; }
alive() {
    local state
    state="$(ps -o stat= -p "$runtime_pid")" || return 1
    [[ -n "$state" && "$state" != *Z* ]]
}
observe() { printf '%s[Demo-Prüfung] %s%s\n' "$color_success" "$*" "$color_reset" | tee -a "$demo_root/observer.log"; }
pause_demo() {
    if [[ "$DEMO_AUTO" == 0 ]]; then
        read -r -p "$color_prompt${1:-Enter: ausführen | Strg+C: abbrechen }$color_reset" _
    fi
}
chapter() {
    # Leave the previous step's results visible until the presenter advances.
    # The first chapter has no preceding results; the last uses the close prompt.
    if [[ "${demo_chapter_started:-0}" == 1 ]]; then
        pause_demo 'Enter: zum nächsten Schritt | Strg+C: abbrechen '
    fi
    demo_chapter_started=1
    # Clear the current pane and move the cursor home, like clear. Keep the
    # scrollback and transcript; this needs no additional external command.
    printf '\033[2J\033[H'
    printf '\n%s%s%s\n' "$color_heading" "$1" "$color_reset"
    printf '\n%sAusgangslage:%s\n  %s\n' "$color_section" "$color_reset" "$2"
    # Optional live evidence is shown before any action or execution prompt.
    if [[ "${6:-}" == show-active ]]; then
        printf '\nNachweis der Ausgangslage durch das Administrationstool:\n'
        admin show-active
        printf '\nOhne aktivierte Policies enthält die Ausgabe keine aktivierten Policy-Einträge. Angezeigte Attribute sind davon unabhängig.\n'
    fi
    printf '\n%sAktion:%s\n  %s\n' "$color_section" "$color_reset" "$3"
    printf '\n%sErwartetes Verhalten:%s\n  %s\n' "$color_section" "$color_reset" "$4"
    printf '\n%sBeobachtung:%s\n  %s\n\n' "$color_section" "$color_reset" "$5"
    pause_demo
}
explain() { printf '\n→ %s\n' "$*"; }
show_command() {
    printf '\n%s$' "$color_command"
    printf ' %q' "$@"
    printf '%s\n' "$color_reset"
}
show_output() {
    local status=0
    printf '%s' "$color_output"
    "$@" || status=$?
    printf '%s' "$color_reset"
    return "$status"
}
admin() {
    local quiet=0
    if [[ "${1:-}" == --quiet ]]; then quiet=1; shift; fi
    local command=("$ADM_TOOL_BIN" --policy-dir "$policy_dir" --attributes-dir "$attribute_dir" "${1:-show-active}")
    if (( quiet == 0 )); then
        # Show the exact executed argv, quoted as a valid Bash command. Internal
        # generation polling stays quiet so it does not obscure the demo output.
        printf '\n[Admin-Tool des Prototyps]\n'
        show_command "${command[@]}"
    fi
    if (( quiet == 0 )); then
        show_output "${command[@]}"
    else
        "${command[@]}"
    fi
}
generations() {
    local output
    output="$(admin --quiet)" || return 1
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
    printf '%s' "$color_config"
    cat "$demo_root/prepared"
    printf '%s' "$color_reset"
    show_command bash "$PROJECT_ROOT/scripts/publish-config.sh" "$demo_root/prepared" "$destination"
    show_output bash "$PROJECT_ROOT/scripts/publish-config.sh" "$demo_root/prepared" "$destination"
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
    show_command rm -- "$policy_dir/$name.policy"
    rm -- "$policy_dir/$name.policy"
    wait_generation policy "${before%% *}" "$offset"
}
access_is() {
    local expected="$1" command="${2:-tails-demo}" uid="${3:--}" file="${4:-$target}" actual
    alive || { fail 'Runtime beendet.'; return 1; }
    local invocation=(python3 "$PROJECT_ROOT/scripts/demo/probe.py" access "$file" "$command" "$uid")
    printf '\n[Zugriffshilfe: probe.py access – prüft eine echte Dateiöffnung mit os.open]\n'
    show_command "${invocation[@]}"
    actual="$("${invocation[@]}")"
    printf '%s[probe.py access → stdout] %s%s\n' "$color_output" "$actual" "$color_reset"
    [[ "$actual" == "$expected" ]] || { fail "Zugriff: erwartet $expected, beobachtet $actual ($command, UID $uid)."; return 1; }
    observe "OK: Erwartet=$expected, beobachtet=$actual (Kommando/comm=$command, Real-UID=$uid, Datei=${file##*/})."
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
    printf '\n[FD-Beobachter: probe.py hold – Ausgabe im rechten unteren Bereich]\n'
    show_command python3 "$PROJECT_ROOT/scripts/demo/probe.py" hold "$target" "$safe" "$probe_dir"
    DEMO_OUTPUT_COLOR="$color_output" DEMO_COLOR_RESET="$color_reset" \
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
    runtime_pid='' probe_pid='' owns_pins=0 demo_chapter_started=0
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
    if pgrep -x tails-pdp >/dev/null; then fail 'Es läuft bereits eine Instanz des Prototyps.'; return 1; fi
    setup_demo_bpffs
    owns_pins=1
    mkdir -p "$policy_dir" "$attribute_dir/subjects" "$attribute_dir/resources"
    printf 'Geschützter Demo-Inhalt\n' > "$target"
    printf 'Weiterhin zulässiger Kontroll-Inhalt\n' > "$safe"
    ln -- "$target" "$demo_root/alias.txt"
    printf 'defcon = 5\n' > "$attribute_dir/system.attributes"
    cd "$demo_root"

    printf 'Prototyp – geführte Live-Demo\nLogs: %s\n' "$demo_root"
    printf 'Eigener bpffs-Mount: vorhandene Host-Pins bleiben unverändert.\n'
    printf 'Links: Erklärung und Aktionen. Rechts oben: Runtime. Rechts unten: FD-Beobachter.\n'
    printf 'Nur die Enter-Taste ist für die Schritte nötig. Strg+C beendet die Demo.\n'
    printf 'allow = Dateiöffnung erlaubt; deny = vom LSM mit EPERM verweigert. Andere Fehler brechen die Demo ab.\n'
    printf 'Die Policygeneration zählt aktivierte Policy-Stände; die Attributgeneration zählt aktivierte Attributstände.\n'
    printf 'show-active zeigt geladene Policies und Werte. Die Zugriffsentscheidung wird zusätzlich mit einer echten Dateiöffnung geprüft.\n'

    # Kapitel 1: Die Durchsetzung erst nach dem nachgewiesenen LSM-Attach prüfen.
    # Der leere Policy-Stand zeigt das Allow-Verhalten ohne passende Deny-Policy.
    chapter '1. Runtime starten und Ausgangszustand prüfen' \
        'Die Demo-Dateien sind vorbereitet. Es läuft noch keine Demo-Runtime und es sind keine Policies geladen.' \
        'Der Prototyp wird gestartet. Dabei wird das eBPF-Programm geladen, die Maps werden vorbereitet und der file_open-Hook wird angehängt. Danach wird die geschützte Datei geöffnet.' \
        'Alle erwarteten Maps existieren, die Runtime läuft und die Dateiöffnung ist erlaubt: Ohne passende Deny-Policy wird kein Zugriff untersagt.' \
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
    chapter '2. Statische Policies: Kommando, Benutzer und Ressource' \
        "Die Dateien sind zunächst zugänglich:
  Geschützte Datei: $target
  Kontrolldatei: $safe
  Hardlink auf die geschützte Datei: $demo_root/alias.txt
  protected.txt und alias.txt bezeichnen dieselbe Datei; control.txt ist eine separate Datei." \
        'Eine Deny-Policy wird für genau drei gemeinsam erforderliche Merkmale veröffentlicht: Real-UID 60001, Kommando cat und die geschützte Ressource. Danach werden diese Merkmale einzeln variiert.' \
        'Nur die passende Kombination auf protected.txt wird verweigert. Eine andere UID, ein anderes Kommando und die separate control.txt bleiben erlaubt. alias.txt wird ebenfalls verweigert, weil Gerät und Inode mit protected.txt übereinstimmen.' \
        'Der Kommando-Filter liest den Namen aus dem Linux-Feld comm. Die Zugriffshilfe setzt diesen Namen für den Test auf cat. Sie führt eine echte Dateiöffnung mit os.open aus und erkennt eine Verweigerung durch EPERM. So lassen sich Kommando und Real-UID gezielt variieren, ohne Benutzerkonten anzulegen. Die effektive UID bleibt root. Das Programm cat wird bei dieser Prüfung nicht gestartet.'
    policy scoped deny '    subject.uid == 60001;' cat
    explain 'Alle drei Filter passen: Die Dateiöffnung muss verweigert werden.'
    access_is deny cat 60001
    explain 'Negativkontrollen: jeweils eine andere UID, ein anderes Kommando oder eine andere Datei. Diese Zugriffe müssen erlaubt bleiben.'
    access_is allow cat 60002
    access_is allow other 60001
    access_is allow cat 60001 "$safe"
    explain 'Der alternative Hardlink-Pfad bezeichnet dieselbe Datei. Die Sperre gilt auch dort.'
    access_is deny cat 60001 "$demo_root/alias.txt"
    admin show-policies
    explain 'Die Policy wird entfernt. Derselbe zuvor verweigerte Zugriff muss wieder möglich sein.'
    remove_policy scoped
    access_is allow cat 60001

    # Kapitel 3: Permit hebt ein gleichzeitig passendes Deny nicht auf.
    # Jede Veröffentlichung/Entfernung aktiviert einen neuen vollständigen Stand.
    chapter '3. Permit, Deny-Vorrang und Policy-Lebenszyklus' \
        'Nach dem Entfernen der vorherigen Policy sind keine Policies aktiviert. Dies wird vor den Änderungen mit show-active angezeigt. In diesem Schritt werden keine Benutzer- oder Kommandofilter verwendet.' \
        'Zuerst wird Permit geladen, dann eine passende Deny-Policy ergänzt und anschließend nur Deny entfernt. Zum Schluss wird auch Permit entfernt.' \
        'Die Zugriffe folgen der Reihenfolge erlaubt → verweigert → erlaubt. Bei gleichzeitig passenden Policies hat Deny Vorrang vor Permit.' \
        'Die Policygeneration ändert sich bei den Veröffentlichungen und Entfernungen. Neue Entscheidungen werden ohne Neustart wirksam. Die Reihenfolge der Dateinamen bestimmt keine Priorität.' show-active
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
        'Eine Deny-Policy mit system.defcon <= 2 wird geladen. Anschließend wird nur der Attributwert von 5 auf 2 und zurück auf 5 geändert.' \
        'Bei 5 ist die Deny-Bedingung falsch und der Zugriff erlaubt. Bei 2 ist sie erfüllt und der Zugriff verweigert. Nach der Rückkehr zu 5 ist er wieder erlaubt.' \
        'Die Policydatei bleibt während der Attributwechsel gleich. Im Log und im Admin-Tool ändert sich der Attributstand; die Runtime muss dafür nicht neu gestartet werden.'
    policy context deny '    system.defcon <= 2;'
    access_is allow
    explain 'DEFCON sinkt auf 2: Die bereits geladene Deny-Policy trifft jetzt zu.'
    attribute system.attributes 'defcon = 2'
    access_is deny
    admin show-attributes
    explain 'DEFCON steigt wieder auf 5: Dieselbe Policy trifft nicht mehr zu.'
    attribute system.attributes 'defcon = 5'
    access_is allow
    remove_policy context

    # Kapitel 5: System-, Subjekt- und Ressourcenattribute sind konjunktiv.
    # Fehlende oder anders typisierte Werte erfüllen den Stringvergleich nicht;
    # das ist hier ein gültiger Attributstand, kein abgelehntes Update wie in 6.
    chapter '5. Subject-/Resource-Attribute und UND-Verknüpfung' \
        'Attribute können für das gesamte System, für einen Benutzer und für eine konkrete Datei hinterlegt werden. Der normale Demo-Zugriff läuft mit Real-UID 0.' \
        'DEFCON wird auf 2, die Rolle von UID 0 auf engineer und die Dateiklassifikation auf internal gesetzt. Eine Deny-Policy verknüpft alle drei Bedingungen mit UND. Danach werden einzelne Werte geändert.' \
        'Deny gilt nur, wenn alle drei Bedingungen erfüllt sind. Rolle intern oder Klassifikation public reichen jeweils aus, damit diese Deny-Policy nicht mehr passt.' \
        'Anschließend werden eine fehlende Rolle und die Zahl 1 statt eines Rollenstrings geprüft. Beide Attributstände sind gültig, erfüllen aber den Vergleich mit "engineer" nicht. Deshalb greift hier kein Deny.'
    attribute system.attributes 'defcon = 2'
    attribute subjects/0.attributes 'position = "engineer"'
    attribute "resources${target}.attributes" 'classification = "internal"'
    policy combined deny $'    system.defcon <= 2;\n    subject.position == "engineer";\n    resource.classification == "internal";'
    access_is deny
    explain 'Nur die Rolle wird engineer → intern geändert. Damit ist eine der drei UND-Bedingungen falsch.'
    attribute subjects/0.attributes 'position = "intern"'
    access_is allow
    attribute subjects/0.attributes 'position = "engineer"'
    explain 'Die Rolle stimmt wieder. Jetzt wird nur die Dateiklassifikation internal → public geändert.'
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
    explain 'Der Rollenstring engineer wird wiederhergestellt: Alle Bedingungen passen und der Zugriff wird verweigert.'
    attribute subjects/0.attributes 'position = "engineer"'
    access_is deny
    admin
    remove_policy combined

    # Kapitel 6: Syntax-/Validierungsfehler dürfen keine neue Generation
    # aktivieren. Nach der Ablehnung muss eine gültige Korrektur weiter möglich sein.
    chapter '6. Ungültige Updates und anschließende Korrektur' \
        'DEFCON steht noch auf 2. Eine passende Deny-Policy wird geladen. Vor jedem fehlerhaften Update werden beide Generationsnummern gespeichert.' \
        'Zuerst wird eine Policy mit fehlendem Semikolon veröffentlicht. Nach ihrer Korrektur wird DEFCON=9 veröffentlicht, obwohl für dieses Attribut nur 1 bis 5 zulässig sind.' \
        'Beide fehlerhaften Updates werden verworfen. Die zuletzt gültigen Generationen und das wirksame Deny bleiben erhalten. Gültige Korrekturen werden anschließend wieder übernommen.' \
        'Rechts oben erscheint die Ablehnung. Links werden die unveränderten Generationen und der weiterhin verweigerte Zugriff geprüft. Der letzte gültige Policy-Stand bleibt aktiv.'
    policy robust deny '    system.defcon <= 2;'
    local before offset
    before="$(generations)"
    offset="$(wc -l < "$demo_root/runtime.log")"
    explain 'Die nächste Policy ist absichtlich syntaktisch fehlerhaft. Sie darf nicht aktiviert werden.'
    printf 'policy "kaputt"\ndeny\n action == "file_open"\n' | publish "$policy_dir/broken.policy"
    wait_log 'POLICY sync failed' "$offset"
    [[ "$(generations)" == "$before" ]] || { fail 'Ungültige Policy änderte die Generation.'; return 1; }
    access_is deny
    explain 'Die fehlerhafte Datei wird durch eine gültige Permit-Policy ersetzt. Das bereits vorhandene Deny hat weiterhin Vorrang.'
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
        'Bisher wurden neue Dateiöffnungen geprüft. Ein Prozess kann eine Datei aber schon geöffnet haben, bevor eine neue Policy veröffentlicht wird.' \
        'Ein Beobachter mit drei offenen FDs zur geschützten Datei und zwei offenen FDs zur Kontrolldatei wird gestartet. Erst im nächsten Schritt wird eine passende Deny-Policy veröffentlicht.' \
        'Zunächst müssen alle fünf FDs offen sein. Nach der Policyaktivierung prüft der Userspace-PEP bestehende FDs erneut und entzieht ausschließlich die drei geschützten.' \
        'FD bedeutet Dateideskriptor: eine offene Dateireferenz in einem Prozess. Rechts unten zeigt True einen offenen FD und False einen geschlossenen. Der Beobachterprozess soll weiterlaufen.'
    start_probe
    chapter '7a. FDs sind offen – jetzt Deny veröffentlichen' \
        'Der Beobachter hält alle fünf FDs offen. Vor der Änderung wird zusätzlich geprüft, dass diese FDs noch auf die erwarteten Dateien verweisen.' \
        'Enter veröffentlicht Deny für die geschützte Datei und das Kommando tails-demo-fd. Die Policyaktivierung löst eine erneute FD-Prüfung aus.' \
        'Die drei geschützten FDs wechseln auf False. Beide Kontroll-FDs bleiben True; der Prozess wird nicht beendet.' \
        'Rechts oben ist die Policyaktivierung mit anschließendem Scan sichtbar. Rechts unten ist der tatsächliche FD-Zustand zu sehen. Ein Logeintrag allein genügt nicht als Nachweis.'
    assert_probe_identity
    policy revoke deny '' tails-demo-fd
    expect_revoked
    explain 'Der selektive Entzug ist bestätigt. Der Beobachter wird jetzt gezielt beendet und die Demo-Policy für das nächste Kapitel entfernt.'
    stop_probe
    remove_policy revoke

    # Kapitel 8: Deny ist bereits geladen, seine Bedingung aber zunächst falsch.
    # Nur die Attributgeneration darf sich durch den Auslöser ändern.
    chapter '8. FD-Entzug ausschließlich durch Attributänderung' \
        'DEFCON steht auf 5. Vor dem Öffnen wird eine Deny-Policy mit system.defcon <= 2 installiert. Die Policy ist aktiviert, ihre Bedingung ist jedoch noch nicht erfüllt.' \
        'Ein neuer Beobachter öffnet drei geschützte und zwei Kontroll-FDs. Danach wird im nächsten Schritt ausschließlich das Systemattribut geändert.' \
        'Solange DEFCON=5 gilt, bleiben alle FDs offen. Der spätere Wechsel auf 2 muss den Entzug ohne Änderung der Policydatei auslösen.' \
        'Eine geladene Policy und eine erfüllte Bedingung sind zu unterscheiden. enabled im Admin-Tool bedeutet, dass die Policy aktiviert ist; ihre Bedingungen werden für den jeweiligen Zugriff ausgewertet.'
    policy revoke deny '    system.defcon <= 2;' tails-demo-fd
    start_probe
    chapter '8a. Nur das Systemattribut ändern' \
        'Die Policy ist bereits geladen und der Beobachter hält seine FDs offen. Die aktuelle Policygeneration wird gespeichert.' \
        'Enter veröffentlicht ausschließlich DEFCON=2. Der Attributloader aktiviert den neuen Wert und löst damit eine FD-Prüfung aus.' \
        'Die Attributgeneration steigt, die Policygeneration bleibt gleich. Nur die drei geschützten FDs werden geschlossen; beide Kontroll-FDs bleiben offen.' \
        'Rechts oben wird ein Scan mit Ursache attributes:<Generation> erwartet. Damit wird der Attributwechsel als Auslöser nachgewiesen. Die Policy bleibt dabei unverändert.'
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
        'Nach Enter wird eine Grenze zwölf Sekunden in der Zukunft berechnet. Die Zeitpolicy wird geladen und die Dateien werden vor dieser Grenze geöffnet. Anschließend wird ohne weitere Konfigurationsänderung gewartet.' \
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
        'Neben Unix-Zeit mit Modulus unterstützt der Prototyp UTC-Zeitfelder. Der vorherige zeitabhängige Policy-Stand wurde entfernt.' \
        'Deny für environment.utc.hour >= 0 und zusätzlich Permit für environment.utc.minute >= 0 werden geladen. Die aktiven Maps werden angezeigt; danach wird nur Deny entfernt.' \
        'Beide Bedingungen sind zu jeder gültigen Tageszeit wahr. Mit beiden Policies gilt Deny-Vorrang; nach dem Entfernen von Deny ist der Zugriff wieder erlaubt.' \
        'Die bewusst immer wahren Vergleiche zeigen die UTC-Felder unabhängig von der Uhrzeit der Vorführung. Das Admin-Tool zeigt die Policies, die Zugriffshilfe prüft deren tatsächliche Wirkung.'
    policy utc deny '    environment.utc.hour >= 0;'
    access_is deny
    policy stream-permit permit '    environment.utc.minute >= 0;'
    explain 'Auch die zusätzliche zeitabhängige Permit-Policy hebt das passende Deny nicht auf.'
    access_is deny
    admin
    explain 'Nur die UTC-Deny-Policy wird entfernt. Das Stream-Permit bleibt zunächst geladen.'
    remove_policy utc
    access_is allow
    remove_policy stream-permit
    explain 'Alle Demo-Policies sind wieder entfernt. Beim Schließen werden Runtime und Hilfsprozesse beendet und die eigenen Maps aufgeräumt. Die Logs bleiben erhalten.'
    observe 'Alle Demo-Kapitel erfolgreich geprüft.'
    printf '\nGrenzen: FD-Schließen holt gelesene Daten nicht zurück; mmap und ptrace-Races sind nicht durch diese Demo abgedeckt.\n'
}
