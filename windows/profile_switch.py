#!/usr/bin/env python3
"""State-aware Samsung G95NC profile switcher for Windows.

Uses samsung_pbpctl_win.py in the same directory. Layout switches can cause
Windows to re-enumerate the monitor; therefore every read and write reacquires
its handle. All INI values are hexadecimal.
"""

import argparse
import configparser
from pathlib import Path
import sys
import time

from samsung_pbpctl_win import find_g95nc, get_vcp, set_vcp

E2 = 0xE2
E3 = 0xE3
SOURCE = 0x60
TIMEOUT = 15.0
POLL = 0.5


def read(code):
    """Return current VCP value or None when the monitor is temporarily absent."""
    handle, desc = find_g95nc()
    # A valid Windows monitor handle can print as None (zero-valued HANDLE).
    if desc is None or "G95NC" not in desc.upper():
        return None
    result = get_vcp(handle, code)
    return result[0] if result else None


def wait_for(predicate, label, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        value = read(E2)
        if value is not None:
            last = value
            mode = classify(value)
            if predicate(value, mode):
                return value
        time.sleep(POLL)
    raise RuntimeError(f"{label} did not settle (last E2={fmt(last)})")


def fmt(value):
    return "unavailable" if value is None else f"{value:04X}"


def classify(e2):
    # Status values measured on the user's G95NC, not the E2 WRITE codes.
    if e2 in (0x3900, 0x3950, 0x395E):
        return "single"
    if e2 in (0x3901, 0x3951):
        return "pbp"
    if e2 in (0x39DF, 0x395F):
        return "pip"
    return "unknown"


def wait_for_read(code, predicate, label, timeout=TIMEOUT):
    deadline = time.monotonic() + timeout
    last = None
    while time.monotonic() < deadline:
        value = read(code)
        if value is not None:
            last = value
            if predicate(value):
                return value
        time.sleep(POLL)
    raise RuntimeError(f"{label} did not settle (last={fmt(last)})")


def write(code, value):
    # Retry monitor discovery around topology changes, but don't repeat a write
    # once Windows has acknowledged it.
    deadline = time.monotonic() + TIMEOUT
    while time.monotonic() < deadline:
        handle, desc = find_g95nc()
        if desc is not None and "G95NC" in desc.upper():
            if set_vcp(handle, code, value):
                print(f"Write {code:02X}={value:02X}: acknowledged")
                return
        time.sleep(POLL)
    raise RuntimeError(f"Could not write {code:02X}={value:02X}; G95NC unavailable")


def target_mode(layout, expected):
    # INI layout is a write command, not a readback value.
    if layout == 0x00:
        return "single"
    if layout == 0x02:
        return "pbp"
    if layout == 0x10:
        return "pip"
    raise ValueError(f"Unsupported profile layout write {layout:02X}; expected 00, 02 or 10")


def switch_layout(wanted):
    current = wait_for(lambda value, mode: mode != "unknown", "Initial E2 reading")
    active = classify(current)
    print(f"Layout: E2={fmt(current)} ({active}) -> {wanted}")
    if active == wanted:
        print("Layout already correct; skipping E2 writes")
        return

    if wanted == "single":
        write(E2, 0x00)
        result = wait_for(lambda value, mode: mode == "single", "Single mode")
        print(f"Single confirmed: E2={fmt(result)}")
        return

    if active == "single":
        # E2=02 doesn't activate PBP from Single. E2=01 restores the retained
        # PIP/PBP layout; only then can 02 or 10 explicitly select another.
        write(E2, 0x01)
        result = wait_for(lambda value, mode: mode in ("pbp", "pip"), "PIP/PBP activation")
        active = classify(result)
        print(f"Restored retained layout: E2={fmt(result)} ({active})")

    if active != wanted:
        command = 0x02 if wanted == "pbp" else 0x10
        write(E2, command)
        result = wait_for(lambda value, mode: mode == wanted, f"{wanted.upper()} layout")
        print(f"{wanted.upper()} confirmed: E2={fmt(result)}")


def load_profile(path, name):
    config = configparser.ConfigParser()
    if not config.read(path, encoding="utf-8"):
        raise ValueError(f"Profiles file not found: {path}")
    if name not in config:
        raise ValueError(f"Unknown profile {name!r}; available: {', '.join(config.sections())}")
    section = config[name]
    layout = int(section["layout"].strip(), 16)
    expected = {int(part.strip(), 16) for part in section["expected"].split(",")}
    source = int(section["source"].strip(), 16)
    topology = int(section["topology"].strip(), 16)
    mode = target_mode(layout, expected)
    for state in expected:
        if classify(state) != mode:
            raise ValueError(f"{name}: expected E2={fmt(state)} conflicts with layout={layout:02X}")
    return mode, expected, source, topology


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("profile", help="profile section name in profiles.ini")
    parser.add_argument("--config", type=Path, default=Path(__file__).with_name("profiles.ini"))
    args = parser.parse_args()
    try:
        mode, expected, source, topology = load_profile(args.config, args.profile)
        expected_text = ",".join(fmt(n) for n in sorted(expected))
        print(f"Target {args.profile}: layout={mode}, E2={expected_text}, E3={fmt(topology)}, 60={fmt(source)}")
        switch_layout(mode)
        current_source = wait_for_read(SOURCE, lambda value: True, "Initial input source")
        if current_source != source:
            print(f"Source: {fmt(current_source)} -> {fmt(source)}")
            write(SOURCE, source)
        else:
            print("Input source already correct; skipping write")
        wait_for_read(SOURCE, lambda value: value == source, "Input source")
        wait_for_read(E3, lambda value: value == topology, "Topology")
        # Late readback check: a physically correct mode may nevertheless have
        # an unrecognized retained-layout signature; report this explicitly.
        actual_e2 = wait_for(lambda value, current_mode: current_mode == mode, "Final layout")
        if actual_e2 not in expected:
            raise RuntimeError(
                f"Physical layout is {mode}, but E2={fmt(actual_e2)} is missing from "
                f"the {args.profile} expected values ({expected_text})"
            )
        print(f"Profile {args.profile} verified: E2={fmt(actual_e2)}, E3={fmt(topology)}, 60={fmt(source)}")
        return 0
    except (RuntimeError, ValueError, KeyError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
