# Samsung Odyssey G95NC — DDC/CI protocol

Vendor VCP codes for PBP/PIP/3PBP, reverse-engineered by tracing the Windows
"Samsung Display Manager" DDC/CI traffic (hooking `DXVA2!SetVCPFeature`) and
confirmed by writing each value back and observing the panel.

Panel is 7680×2160 (two UHD halves). All values are hex.

## `0xE2` — mode and layout (write to set)

| command | result |
|--------:|--------|
| `0x00` | off / single source (exits PBP/PIP) |
| `0x01` | PBP on, 2-way (last-used split) |
| `0x02` | PBP 2-way, large-left / small-right |
| `0x03` | PBP 2-way, 50/50 |
| `0x04` | PBP 2-way, large-left (~21:9 left pane) |
| `0x05` | PBP 2-way, uneven |
| `0x06` | 3PBP, narrow/square center, larger sides |
| `0x07` | 3PBP, 50/25/25 (large-left) |
| `0x08` | 3PBP, 25/50/25 (large-middle, 16:9 middle) |
| `0x09` | 3PBP, 25/25/50 (large-right) |
| `0x10` | PIP |

Entering 3PBP from 2-way or from off works with a single `0xE2` write — no
preceding source/topology sequence is required.

### The status-readback gotcha

`getvcp E2` does **not** return the command value. It returns a *status* of the
form `0x39NN`:

| command | status readback |
|--------:|-----------------|
| 2-way on (`0x01`/`0x03`) | `0x3901` |
| `0x07` | `0x3909` |
| `0x08` | `0x390b` |
| `0x09` | `0x390d` |
| PIP (`0x10`) | `0x390f` |

For the 3PBP buckets the status low byte is `2*command - 5`. Replaying the
*status* value (e.g. `0x0b`) does nothing — you must write the *command* value
(`0x08`). A 3PBP layout write briefly drops DDC while the monitor re-enumerates.

## `0xE3` — pane source

16-bit value: `(channel << 8) | source_code`

- channel: `0x00` left/main, `0x01` middle, `0x02` right
- source_code: `0x00` HDMI1, `0x01` HDMI2, `0x02` HDMI3, `0x10` DisplayPort

```
setvcp E3 0x0110   # middle pane -> DisplayPort
setvcp E3 0x0201   # right pane  -> HDMI2
```

`getvcp E3` returns a packed status (high byte `0xc0` in 3PBP, `0x10` in 2-way);
the low bytes encode current pane sources. Layout/ratio changes do not alter
sources.

## Other codes

- `0xE8` — PBP/PIP sound source. `max 0x02` (three options).
- `0x60` — standard MCCS input source. Confirmed: `0x0f` DisplayPort,
  `0x11` HDMI-1, `0x12` HDMI-2. (`0x32`/decimal 50 appears in capability data;
  unconfirmed.)

## On 21:9 in 3PBP

The 3PBP 25/50/25 layout makes the middle pane 16:9 (3840×2160). A 21:9 (≈5120)
middle is **not** exposed: the firmware's only 3PBP EDID aspect flag is
`SEC_EDID_FLAG_3PBP_QUARTER`, while 21:9 appears as a 2-way feature
(`SEC_EDID_FLAG_PBP_21_9` paired with `PBP_11_9` = uneven 2-way split, 5120+2560).
So a true 21:9 region is available in 2-way (`0xE2 = 0x04`), not in 3PBP.

## Reproducing / extending

Use `windows/frida_vcp_trace.py` to log a DDC-using app's `SetVCPFeature` calls,
or `windows/samsung_pbpctl_win.py` to probe codes directly and read back status.
The same approach should generalize to other Samsung PBP-capable monitors.
