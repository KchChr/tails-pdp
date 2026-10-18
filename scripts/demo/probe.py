#!/usr/bin/env python3
"""Syscall helpers for the Bash demo; no external Python dependencies."""
import argparse
import ctypes
import errno
import json
import os
from pathlib import Path
import time


def set_command(name):
    if ctypes.CDLL(None, use_errno=True).prctl(15, name.encode(), 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "prctl(PR_SET_NAME)")


def is_open(fd):
    try:
        os.fstat(fd)
        return True
    except OSError as error:
        if error.errno != errno.EBADF:
            raise
        return False


def save(path, value):
    temporary = path.with_suffix(".tmp")
    temporary.write_text(json.dumps(value))
    temporary.replace(path)


def access(path, command, uid):
    set_command(command)
    # Exercise real-UID matching without creating accounts or changing DAC rights.
    if uid != "-":
        os.setresuid(int(uid), 0, 0)
    try:
        fd = os.open(path, os.O_RDONLY)
    except OSError as error:
        if error.errno != errno.EPERM:
            raise
        print("deny")
    else:
        os.close(fd)
        print("allow")


def hold(target, safe, directory):
    def message(text):
        print(f"{os.environ.get('DEMO_OUTPUT_COLOR', '')}[FD-Beobachter: probe.py hold] {text}{os.environ.get('DEMO_COLOR_RESET', '')}", flush=True)

    set_command("tails-demo-fd")
    root = Path(directory)
    protected = [os.open(target, os.O_RDONLY) for _ in range(3)]
    controls = [os.open(safe, os.O_RDONLY) for _ in range(2)]
    message(f"PID {os.getpid()}: drei geschützte FDs {protected}, zwei Kontroll-FDs {controls} geöffnet.")
    save(root / "ready.json", {"pid": os.getpid(), "protected": protected, "controls": controls})
    previous = None
    while True:
        opened = [is_open(fd) for fd in protected]
        safe_open = [is_open(fd) for fd in controls]
        state = (opened, safe_open)
        if state != previous:
            message(f"Geschützte FDs offen: {opened} | Kontroll-FDs offen: {safe_open} | Prozess läuft")
            save(root / "state.json", {"protected": opened, "controls": safe_open, "unix_ns": time.time_ns()})
            previous = state
        # Stay alive after revocation to demonstrate that the process is not killed.
        time.sleep(0.05)


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="probe.py",
        description="Zugriffshilfe und FD-Beobachter für die Demo des Prototyps (Linux).",
        epilog="Beispiel: python3 scripts/demo/probe.py access demo/files/protected.txt cat -",
    )
    modes = parser.add_subparsers(dest="mode", required=True, metavar="{access,hold}")
    access_parser = modes.add_parser(
        "access", help="Eine Dateiöffnung prüfen und allow oder deny ausgeben.",
        description="Führt os.open aus: allow bei Erfolg, deny bei EPERM. Andere Fehler führen zum Abbruch.",
    )
    access_parser.add_argument("path", metavar="DATEI", help="Pfad der zu öffnenden Datei.")
    access_parser.add_argument("command", metavar="KOMMANDO", help="Unter Linux geführter Kommandoname comm für den Kommando-Filter; das Programm wird nicht gestartet.")
    access_parser.add_argument("uid", metavar="UID", help="Real-UID für den Test; '-' lässt die UID unverändert. Eine UID-Änderung benötigt root; die effektive UID bleibt 0.")
    hold_parser = modes.add_parser(
        "hold", help="Geschützte FDs und Kontroll-FDs öffnen und ihren Zustand beobachten.",
        description="Öffnet drei geschützte und zwei Kontroll-FDs. Der Prozess bleibt auch nach einem FD-Entzug aktiv und läuft bis zum Beenden weiter.",
    )
    hold_parser.add_argument("target", metavar="GESCHÜTZTE_DATEI", help="Datei für die drei geschützten FDs.")
    hold_parser.add_argument("safe", metavar="KONTROLLDATEI", help="Datei für die zwei weiterhin zulässigen Kontroll-FDs.")
    hold_parser.add_argument("directory", metavar="AUSGABEVERZEICHNIS", help="Vorhandenes Verzeichnis für ready.json und state.json.")
    arguments = parser.parse_args(argv)
    if arguments.mode == "access":
        access(arguments.path, arguments.command, arguments.uid)
    else:
        hold(arguments.target, arguments.safe, arguments.directory)


if __name__ == "__main__":
    main()
