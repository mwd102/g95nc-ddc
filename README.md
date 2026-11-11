# Samsung Odyssey G95NC — DDC/CI Control

Reverse-engineered DDC/CI (VCP) control for the **Samsung Odyssey G95NC** (Neo G9
57", Dual UHD 7680×2160), including **PBP, PIP, and 3PBP** layouts and per-pane
source selection — the features Samsung's own app exposes slowly or not at all.

All control happens over two vendor VCP codes: `0xE2` (mode/layout) and `0xE3`
(pane source). See [`docs/protocol.md`](docs/protocol.md) for the full map.

## Firmware compatibility

- Tested and working on firmware `M-C9557GGPA-1009.2`.
- Users report that it does not work on firmware `1007.0`.
- Compatibility with firmware `1008.2` is currently unknown.

## Quick start (Windows)

`windows/samsung_pbpctl_win.py` drives the monitor directly via the Win32
monitor-configuration API (`dxva2.dll`) — no vendor software required.

```sh
python windows/samsung_pbpctl_win.py status          # read current state
python windows/samsung_pbpctl_win.py set e2 0008      # 3PBP 25/50/25 (large middle)
python windows/samsung_pbpctl_win.py set e3 0110      # middle pane -> DisplayPort
python windows/samsung_pbpctl_win.py set e2 0000      # back to single source
```

It auto-selects the G95NC by probing which monitor's `0xE2` reports the
`0x39xx` PBP/PIP status family.

## Layouts at a glance (`setvcp E2`)

| value | mode | name | layout |
|------:|------|:----:|:------:|
| `0x00` | off / single source | S | 100 |
| `0x01` | PBP 2-way (last split) | — | — |
| `0x03` | PBP 2-way 50/50 | 2E | 50/50 |
| `0x04` | PBP 2-way 67/33 (large-left) | 2L | 67/33 |
| `0x07` | 3PBP 50/25/25 (large-left) | 3L | 50/25/25 |
| `0x08` | 3PBP 25/50/25 (large-middle) | 3C | 25/50/25 |
| `0x09` | 3PBP 25/25/50 (large-right) | 3R | 25/25/50 |
| `0x06` | 3PBP square-center / larger sides | — | — |
| `0x10` | PIP | PIP | — |

**Naming:** The number indicates the number of panels; L, C, and R identify the
largest panel's position, while E indicates equal-sized panels. S means
single source. Layout: Relative panel widths, ordered left to right.

**Note:** A dash indicates that no layout name or ratio has been assigned.
The `--ensure` feature currently supports only S, 2E, and 2L; other layouts
remain accessible through raw `set` commands.

## State-aware layout switching (`--ensure`)

The optional `--ensure` flag provides state-aware PBP layout switching
with status verification. It avoids unnecessary DDC writes and handles
transitions between single-source and PBP modes.

```sh
python windows/samsung_pbpctl_win.py set e2 04 --ensure  # 2L (67/33)
python windows/samsung_pbpctl_win.py set e2 03 --ensure  # 2E (50/50)
python windows/samsung_pbpctl_win.py set e2 00 --ensure  # S (single source)
```

When enabled, the controller:
- Checks the current layout before issuing commands.
- Automatically enables PBP when transitioning from single-source mode.
- Skips redundant commands when the requested layout is already active.
- Re-enumerates the monitor and polls for the expected status.
- Returns a nonzero exit code if verification fails or times out.

The default timeout is 10 seconds and can be adjusted:

```sh
python windows/samsung_pbpctl_win.py set e2 04 --ensure --timeout 15
```

Currently supported layouts are S (`0x00`), 2E (`0x03`), and 2L
(`0x04`). Other layouts remain accessible through raw `set` commands.

`--ensure` currently supports VCP `0xE2` only.

## Linux (ddcutil)

`ddcutil/SAM-Odyssey-G95NC.mccs` is a [ddcutil](https://www.ddcutil.com/) user-defined
feature file for the same codes. Fill in `MODEL`/`PRODUCT_CODE` from your own
`ddcutil detect`, drop it in `~/.local/share/ddcutil/`, then e.g.
`ddcutil setvcp E2 0x08`.

## Other tools

`windows/frida_vcp_trace.py` is the Frida tracer used to reverse the protocol —
it logs `DXVA2!SetVCPFeature`/`GetVCPFeatureAndVCPFeatureReply` traffic from any
DDC-using app and offers a replay console. Useful for extending this to other
Samsung models.
