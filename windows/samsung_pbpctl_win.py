#!/usr/bin/env python3
"""Standalone Windows DDC/CI control for the Samsung Odyssey G95NC.

No Frida, no Samsung Display Manager. Talks to the monitor directly through the
Win32 monitor-configuration API (dxva2.dll), so it cannot be crashed by SDM and
does not depend on SDM being installed or running.

The G95NC is auto-selected by probing each physical monitor's VCP 0xe2 and
keeping the one whose status reads back in the 0x39xx family (its PBP/PIP status
register). See outputs/samsung-g95nc-control-kb.md for the protocol.

Examples:
  python samsung_pbpctl_win.py list
  python samsung_pbpctl_win.py status
  python samsung_pbpctl_win.py get e2
  python samsung_pbpctl_win.py set e2 0007          # enter 3PBP (large-left/two-small)
  python samsung_pbpctl_win.py seq e2 0001 e2 0007  # PBP on, then 3PBP layout
All codes/values are hex.
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
    """Yield (handle, description) for every physical monitor on the system."""
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


def find_g95nc():
    """Select the physical monitor whose 0xe2 status reads back as 0x39xx."""
    fallback = None
    for handle, desc in _physical_monitors():
        if fallback is None:
            fallback = (handle, desc)
        res = get_vcp(handle, 0xE2)
        if res and ((res[0] >> 8) & 0xFF) == 0x39:
            return handle, desc
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
    time.sleep(settle)  # the monitor updates its status register a beat after the write
    res = get_vcp(handle, code)
    back = f"0x{res[0]:04x}" if res else "n/a"
    print(f"  SET 0x{code:02x}=0x{value:04x} -> ok={ok}  readback=0x{code:02x}:{back}")
    return 0 if ok else 1


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
    p_seq = sub.add_parser("seq", help="write a sequence: code value code value ...")
    p_seq.add_argument("pairs", nargs="+")
    args = parser.parse_args()

    if args.cmd == "list":
        return cmd_list(args)

    handle, desc = find_g95nc()
    if handle is None:
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
