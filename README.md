# scte35-check

Pure-Python SCTE-35 analyser for MPEG-TS (`.ts`) files. No external dependencies.

## What it shows

For every **Splice Insert** command in the stream:

| Field | Description |
|---|---|
| Stream Time (insert) | When the SCTE-35 packet arrived — measured from the nearest video/audio PTS |
| Stream Time (splice) | When the splice should execute — the `splice_time` PTS from the command |
| Lead time | Gap between the two (how much advance notice the encoder gave) |
| Duration | Break length and auto/manual return flag |
| Event ID | 32-bit splice event identifier |
| Program | MPEG program number the cue belongs to |

Times are shown relative to the first PCR in the stream, so they match the playback position in the file (not the raw 90 kHz clock value).

## Usage

```
python scte35_check.py <file.ts> [file2.ts ...]
```

### Example output

```
SCTE-35 Analysis: tsp11301.ts
========================================================================
  Total TS packets : 4,503,611
  Stream duration  : 00:19:47.880
  PMT PID(s)       : 0x01E0
  PCR PID          : 0x0021
  SCTE-35 PID(s)   : 0x0BB8
  SCTE-35 events   : 1

SPLICE INSERT Events
------------------------------------------------------------------------
      Pkt#     PID  Prog      Event ID  Type     Stream Time (insert)  Stream Time (splice)      Lead  Duration
------------------------------------------------------------------------
  2,109,397    3000     1  0x00000001  OUT      00:09:17.129      00:09:21.133        4.004s  180.000s (auto-return)
------------------------------------------------------------------------
  Splice OUT (ad start) : 1
  Splice IN  (ad end)   : 0
  Cancelled             : 0

Ad Break Summary
------------------------------------------------------------------------
  Event 0x00000001  (program 1)
    Trigger inserted at : 00:09:17.129  (PTS of nearest A/V packet)
    Command executes at : 00:09:21.133  (splice_time PTS)
    Lead time           : 4.004s
    Break end           : —
    Break duration      : 180.000s (auto-return)
    Unique program ID   : 1
```

## How it works

1. **PAT → PMT walk** — SCTE-35 PIDs (stream type `0x86`) are discovered automatically; no manual PID input needed.
2. **PCR tracking** — the PCR PID is read from the PMT; the first PCR value anchors all displayed times to the start of the file.
3. **PES PTS tracking** — video and audio elementary streams are tracked so the tool can report the insertion time (when the cue arrived) separately from the execution time (when the splice fires).
4. **Section reassembly** — SCTE-35 sections that span multiple TS packets are correctly reassembled before parsing.
5. **M2TS support** — 192-byte packets with a 4-byte timestamp prefix are detected and handled automatically.

## Supported commands

| Type | Shown |
|---|---|
| `splice_insert` (0x05) | Full detail — OUT/IN/CANCEL, times, duration, avail info |
| `splice_null`, `time_signal`, etc. | Listed in "Other SCTE-35 Commands" section |

## Requirements

Python 3.7+, stdlib only.
