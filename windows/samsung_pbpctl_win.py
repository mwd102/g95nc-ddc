#!/usr/bin/env python3
"""Standalone Windows DDC/CI control for the Samsung Odyssey G95NC.

No Frida, no Samsung Display Manager. Talks to the monitor directly through the
Win32 monitor-configuration API (dxva2.dll), so it cannot be crashed by SDM and
does not depend on SDM being installed or running.

The G95NC is auto-selected by probing each physical monitor's VCP 0xE2 and
identifying the 0x39xx PBP/PIP status register.
See outputs/samsung-g95nc-control-kb.md for the protocol.

Commands:
  list       List detected physical monitors.
  status     Read key monitor registers.
  get        Read a VCP register.
  set        Write a VCP register.
  seq        Execute multiple VCP writes.

Examples:
  python samsung_pbpctl_win.py list
  python samsung_pbpctl_win.py status
  python samsung_pbpctl_win.py get e2
  python samsung_pbpctl_win.py set e2 0007
  python samsung_pbpctl_win.py seq e2 0001 e2 0007
  python samsung_pbpctl_win.py set e2 04 --ensure
  python samsung_pbpctl_win.py set e2 03 --ensure
  python samsung_pbpctl_win.py set e2 00 --ensure

The optional --ensure flag provides state-aware E2 layout switching:
  - Applies to VCP 0xE2 layout commands only.
  - Skips writes when the requested layout is already active.
  - Enables PBP before selecting a layout when necessary.
  - Skips redundant writes if enabling PBP restores the target layout.
  - Reacquires the monitor after topology changes.
  - Polls for the expected status with bounded retries and a timeout.
  - Returns a nonzero exit code if verification fails.

Layouts currently supported by --ensure:
  S     Single display
  2E    Two equal regions
  2L   Two uneven regions, larger left

Other layouts remain accessible through raw set commands.

All VCP codes and values are hexadecimal.
"""

import argparse
import ctypes
import sys
import time
from ctypes import wintypes


dxva2 = ctypes.windll.dxva2
user32 = ctypes.windll.user32


class PHYSICAL_MONITOR(ctypes.Structure):
    _fields_ = [
        ("hPhysicalMonitor", wintypes.HANDLE),
        ("szPhysicalMonitorDescription", wintypes.WCHAR * 128),
    ]


MONITORENUMPROC = ctypes.WINFUNCTYPE(
    wintypes.BOOL, wintypes.HMONITOR, wintypes.HDC,
    ctypes.POINTER(wintypes.RECT), wintypes.LPARAM,
)


def _enum_hmonitors():
    handles = []

    def _cb(hmon, hdc, lprc, lparam):
        handles.append(hmon)
        return True

    user32.EnumDisplayMonitors(None, None, MONITORENUMPROC(_cb), 0)
    return handles


def _physical_monitors():
    """Yield (handle, description) for every enumerated physical monitor."""
    for hmon in _enum_hmonitors():
        count = wintypes.DWORD()
        if not dxva2.GetNumberOfPhysicalMonitorsFromHMONITOR(hmon, ctypes.byref(count)):
            continue
        if count.value == 0:
            continue
        arr = (PHYSICAL_MONITOR * count.value)()
        if not dxva2.GetPhysicalMonitorsFromHMONITOR(hmon, count.value, arr):
            continue
        for pm in arr:
            yield pm.hPhysicalMonitor, pm.szPhysicalMonitorDescription


def get_vcp(handle, code):
    """Return (current, maximum) for a VCP code, or None on failure."""
    vct = wintypes.DWORD()
    cur = wintypes.DWORD()
    mx = wintypes.DWORD()
    ok = dxva2.GetVCPFeatureAndVCPFeatureReply(
        handle, ctypes.c_byte(code & 0xFF),
        ctypes.byref(vct), ctypes.byref(cur), ctypes.byref(mx),
    )
    if not ok:
        return None
    return cur.value, mx.value


def set_vcp(handle, code, value):
    return bool(dxva2.SetVCPFeature(handle, ctypes.c_byte(code & 0xFF), wintypes.DWORD(value & 0xFFFFFFFF)))


def find_g95nc(strict=False):
    """Find a G95NC by its E2 status; retain legacy fallback unless strict.

    A physical monitor handle may appear as None on some systems even when
    DDC calls using it work, so presence is identified by description/status.
    """
    fallback = None
    for handle, desc in _physical_monitors():
        if fallback is None:
            fallback = (handle, desc)
        res = get_vcp(handle, 0xE2)
        if res and (res[0] & 0xFF00) == 0x3900:
            if not strict or "G95NC" in desc.upper():
                return handle, desc
    if strict:
        return None, None
    return fallback if fallback else (None, None)


def parse_hex(token):
    return int(token, 16)


def cmd_list(_args):
    for handle, desc in _physical_monitors():
        e2 = get_vcp(handle, 0xE2)
        tag = " <- G95NC" if (e2 and ((e2[0] >> 8) & 0xFF) == 0x39) else ""
        e2s = f"0x{e2[0]:04x}" if e2 else "n/a"
        print(f"  handle={handle} desc='{desc}' e2={e2s}{tag}")
    return 0


def cmd_status(handle):
    labels = {
        0xE2: "mode/layout status",
        0xE3: "source/topology",
        0xE8: "pip/pbp sound",
        0x60: "input source (MCCS)",
    }
    for code, label in labels.items():
        res = get_vcp(handle, code)
        if res:
            print(f"  0x{code:02x} {label:<22} current=0x{res[0]:04x} max=0x{res[1]:04x}")
        else:
            print(f"  0x{code:02x} {label:<22} (read failed)")
    return 0


def cmd_get(handle, code):
    res = get_vcp(handle, code)
    if res is None:
        print(f"  GET 0x{code:02x} -> read failed")
        return 1
    print(f"  GET 0x{code:02x} -> current=0x{res[0]:04x} max=0x{res[1]:04x}")
    return 0


def cmd_set(handle, code, value, settle=0.4):
    ok = set_vcp(handle, code, value)
    time.sleep(settle)
    res = get_vcp(handle, code)
    back = f"0x{res[0]:04x}" if res else "n/a"
    print(f"  SET 0x{code:02x}=0x{value:04x} -> ok={ok}  readback=0x{code:02x}:{back}")
    return 0 if ok else 1


# Confirmed PBP status values used to validate activation (not all layouts).
KNOWN_PBP_STATES = {0x39D1, 0x39D3, 0x39D7, 0x39DB}

# Only these command-to-status pairs have been confirmed for --ensure.
# Other raw E2 values remain available without --ensure.
E2_STATUS = {
    0x00: {0x39D0, 0x39D2},  # S: observed single-source variants
    0x03: 0x39D1,  # 2E
    0x04: 0x39D3,  # 2L
}


def read_e2_until(deadline, expected=None, delay=0.5):
    """Poll newly enumerated DDC handles until the desired state is observed.

    A successful DDC write can precede the monitor's E2 status update.
    Do not resend writes while waiting for that status change.
    """
    last_state = None
    while time.monotonic() < deadline:
        handle, desc = find_g95nc(strict=True)
        if desc is not None:
            result = get_vcp(handle, 0xE2)
            if result is not None and (result[0] & 0xFF00) == 0x3900:
                state = result[0]
                if state != last_state:
                    print(f"  E2 status=0x{state:04x}", flush=True)
                    last_state = state
                valid = expected if isinstance(expected, (set, frozenset)) else {expected}
                if expected is None or state in valid:
                    return state
        remaining = deadline - time.monotonic()
        if remaining > 0:
            time.sleep(min(delay, remaining))
    return None


def ensure_e2(value, timeout=10.0):
    if value not in E2_STATUS:
        print(f"--ensure: E2 value 0x{value:02x} has no verified status mapping; use raw set", file=sys.stderr)
        return 2

    deadline = time.monotonic() + timeout
    target = E2_STATUS[value]
    targets = target if isinstance(target, set) else {target}
    single_states = E2_STATUS[0x00]
    current = read_e2_until(deadline)
    if current is None:
        print("--ensure: unable to read initial E2 state", file=sys.stderr)
        return 1
    if current in targets:
        print("  Already at requested layout; no writes needed")
        return 0

    # Only one intermediate transition is needed when entering 2-way PBP
    # from single source; otherwise go directly to the requested layout.
    commands = ([0x01] if current in single_states and value != 0x00 else []) + [value]
    for step, command in enumerate(commands, start=1):
        if time.monotonic() >= deadline:
            print("--ensure: deadline exceeded", file=sys.stderr)
            return 1
        handle, desc = find_g95nc(strict=True)
        if desc is None:
            print("--ensure: monitor unavailable before write", file=sys.stderr)
            return 1
        ok = set_vcp(handle, 0xE2, command)
        print(f"  Step {step}/{len(commands)}: SET E2 0x{command:02x} -> ok={ok}")
        if not ok:
            return 1
        if command == 0x01:
            state = read_e2_until(deadline, expected=KNOWN_PBP_STATES)
        else:
            state = read_e2_until(deadline, expected=targets)
        if state is None:
            print(f"--ensure: failed to verify E2 transition after 0x{command:02x}", file=sys.stderr)
            return 1
        if state in targets:
            if command == 0x01:
                print("  Requested layout restored by PBP enable; skipping final E2 write")
            break
    if state not in targets:
        print("--ensure: requested layout not reached", file=sys.stderr)
        return 1
    print(f"  Verified target E2 status=0x{state:04x}")
    return 0


def main():
    parser = argparse.ArgumentParser(description="Standalone Windows DDC control for Samsung G95NC.")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list", help="list physical monitors")
    sub.add_parser("status", help="read key PBP/PIP/source registers")
    p_get = sub.add_parser("get", help="read one VCP code (hex)")
    p_get.add_argument("code")
    p_set = sub.add_parser("set", help="write one VCP code (hex) = value (hex)")
    p_set.add_argument("code")
    p_set.add_argument("value")
    p_set.add_argument("--ensure", action="store_true", help="state-aware verified E2 layout transition")
    p_set.add_argument("--timeout", type=float, default=10.0, help="soft timeout for --ensure (seconds)")
    p_seq = sub.add_parser("seq", help="write a sequence: code value code value ...")
    p_seq.add_argument("pairs", nargs="+")
    args = parser.parse_args()

    if args.cmd == "list":
        return cmd_list(args)

    if args.cmd == "set" and args.ensure:
        code, value = parse_hex(args.code), parse_hex(args.value)
        if code != 0xE2:
            print("--ensure currently supports E2 layout commands only", file=sys.stderr)
            return 2
        if args.timeout <= 0:
            print("--timeout must be positive", file=sys.stderr)
            return 2
        return ensure_e2(value, args.timeout)

    handle, desc = find_g95nc()
    if desc is None:
        print("no physical monitor found", file=sys.stderr)
        return 2
    print(f"[g95nc] handle={handle} desc='{desc}'")

    if args.cmd == "status":
        return cmd_status(handle)
    if args.cmd == "get":
        return cmd_get(handle, parse_hex(args.code))
    if args.cmd == "set":
        return cmd_set(handle, parse_hex(args.code), parse_hex(args.value))
    if args.cmd == "seq":
        if len(args.pairs) % 2 != 0:
            print("seq needs an even number of code/value tokens", file=sys.stderr)
            return 2
        rc = 0
        for i in range(0, len(args.pairs), 2):
            rc |= cmd_set(handle, parse_hex(args.pairs[i]), parse_hex(args.pairs[i + 1]))
            time.sleep(0.2)
        return rc
    return 0


if __name__ == "__main__":
    sys.exit(main())
