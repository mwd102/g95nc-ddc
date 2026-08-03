# Samsung Odyssey G95NC — DDC/CI Control

Reverse-engineered DDC/CI (VCP) control for the **Samsung Odyssey G95NC** (Neo G9
57", Dual UHD 7680×2160), including **PBP, PIP, and 3PBP** layouts and per-pane
source selection — the features Samsung's own app exposes slowly or not at all.

All control happens over two vendor VCP codes: `0xE2` (mode/layout) and `0xE3`
(pane source). See [`docs/protocol.md`](docs/protocol.md) for the full map.

## Firmware compatibility

- Tested and working on firmware `M-C9557GGPA-1009.2`.
- Users report that it does not work on firmware `1008.2`.

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

| value | mode |
|------:|------|
| `0x00` | off / single source |
| `0x01` | PBP 2-way (last split) |
| `0x03` | PBP 2-way 50/50 |
| `0x07` | 3PBP 50/25/25 (large-left) |
| `0x08` | 3PBP 25/50/25 (large-middle) |
| `0x09` | 3PBP 25/25/50 (large-right) |
| `0x06` | 3PBP square-center / larger sides |
| `0x10` | PIP |

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
