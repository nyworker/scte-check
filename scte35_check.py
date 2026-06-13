#!/usr/bin/env python3
"""SCTE-35 checker for MPEG-TS (.ts) files.

Usage: python scte35_check.py <file.ts> [file2.ts ...]
"""

import sys
from pathlib import Path
from dataclasses import dataclass, field
from typing import Optional, List, Dict

TS_PACKET_SIZE = 188
SYNC_BYTE = 0x47
PAT_PID = 0
SCTE35_STREAM_TYPE = 0x86
PTS_MAX = 1 << 33  # 33-bit PTS wraps at ~26.5 hours

# Stream types that carry PES with PTS (video / audio)
PES_STREAM_TYPES = {
    0x01, 0x02,  # MPEG-1/2 video
    0x03, 0x04,  # MPEG-1/2 audio
    0x0F,        # AAC
    0x11,        # AAC-LATM
    0x1B,        # H.264
    0x24,        # H.265 / HEVC
    0x81,        # AC-3
}


# ── Time helpers ─────────────────────────────────────────────────────────────

def pts_to_seconds(pts: int) -> float:
    return pts / 90000.0


def format_seconds(secs: float) -> str:
    h = int(secs // 3600)
    m = int((secs % 3600) // 60)
    s = secs % 60
    return f"{h:02d}:{m:02d}:{s:06.3f}"


def format_pts(pts: Optional[int]) -> str:
    return "N/A" if pts is None else format_seconds(pts_to_seconds(pts))


def relative_seconds(pts: int, pts_adj: int, first_pcr: int) -> float:
    """Offset from stream start: (pts + pts_adj − first_pcr) mod 2^33, in seconds."""
    adjusted = (pts + pts_adj) & (PTS_MAX - 1)
    diff = (adjusted - first_pcr) & (PTS_MAX - 1)
    return pts_to_seconds(diff)


# ── Low-level packet helpers ──────────────────────────────────────────────────

def _extract_pcr_base(pkt: bytes) -> Optional[int]:
    """Extract 33-bit PCR base (90 kHz) from a TS packet adaptation field."""
    afc = (pkt[3] >> 4) & 0x03
    if afc not in (2, 3) or len(pkt) < 12:
        return None
    if pkt[4] < 6:  # adaptation_field_length
        return None
    if not (pkt[5] & 0x10):  # PCR_flag
        return None
    b = pkt[6:11]
    return (b[0] << 25) | (b[1] << 17) | (b[2] << 9) | (b[3] << 1) | (b[4] >> 7)


def _extract_pes_pts(payload: bytes) -> Optional[int]:
    """Extract PTS (90 kHz ticks) from the start of a PES payload."""
    if len(payload) < 14:
        return None
    if payload[0] != 0x00 or payload[1] != 0x00 or payload[2] != 0x01:
        return None
    # Some stream_ids don't carry PTS (padding, private_stream_2, …)
    if payload[3] in (0xBE, 0xBF, 0xF0, 0xF1, 0xF2, 0xF8, 0xFF):
        return None
    pts_dts_flags = (payload[7] >> 6) & 0x03
    if pts_dts_flags == 0:
        return None
    b = payload[9:14]
    return (
        ((b[0] & 0x0E) << 29) |
        (b[1] << 22) |
        ((b[2] & 0xFE) << 14) |
        (b[3] << 7) |
        (b[4] >> 1)
    )


# ── Bit reader ────────────────────────────────────────────────────────────────

class BitReader:
    def __init__(self, data: bytes):
        self.data = data
        self.bit_pos = 0

    def read(self, n: int) -> int:
        result = 0
        for _ in range(n):
            byte_idx = self.bit_pos >> 3
            bit_idx = 7 - (self.bit_pos & 7)
            if byte_idx < len(self.data):
                result = (result << 1) | ((self.data[byte_idx] >> bit_idx) & 1)
            self.bit_pos += 1
        return result


# ── SCTE-35 data classes ──────────────────────────────────────────────────────

@dataclass
class SpliceTime:
    specified: bool
    pts: Optional[int] = None

    def format(self, pts_adj: int = 0, first_pcr: Optional[int] = None) -> str:
        if not self.specified:
            return "immediate"
        if self.pts is None:
            return "N/A"
        if first_pcr is not None:
            return format_seconds(relative_seconds(self.pts, pts_adj, first_pcr))
        return format_pts(self.pts)

    def __str__(self) -> str:
        return self.format()


@dataclass
class BreakDuration:
    auto_return: bool
    duration_pts: int

    @property
    def seconds(self) -> float:
        return pts_to_seconds(self.duration_pts)

    def __str__(self) -> str:
        ar = "auto-return" if self.auto_return else "manual-return"
        return f"{self.seconds:.3f}s ({ar})"


@dataclass
class SpliceInsert:
    event_id: int
    cancelled: bool
    out_of_network: bool = False
    program_splice: bool = True
    splice_immediate: bool = False
    splice_time: Optional[SpliceTime] = None
    break_duration: Optional[BreakDuration] = None
    unique_program_id: int = 0
    avail_num: int = 0
    avails_expected: int = 0

    @property
    def pts(self) -> Optional[int]:
        if self.splice_time and self.splice_time.specified:
            return self.splice_time.pts
        return None


@dataclass
class SCTE35Event:
    pid: int
    program: int
    packet_num: int
    pts_adjustment: int
    command_type: int
    command_name: str
    # PTS of the nearest video/audio PES packet (the "trigger insertion time")
    packet_pts: Optional[int] = None
    splice_insert: Optional[SpliceInsert] = None
    raw_hex: str = ""


# ── SCTE-35 section parsing ───────────────────────────────────────────────────

def _parse_splice_time(br: BitReader) -> SpliceTime:
    specified = bool(br.read(1))
    if specified:
        br.read(6)  # reserved
        pts = br.read(33)
        return SpliceTime(specified=True, pts=pts)
    br.read(7)  # reserved
    return SpliceTime(specified=False)


def _parse_break_duration(br: BitReader) -> BreakDuration:
    auto_return = bool(br.read(1))
    br.read(6)  # reserved
    duration = br.read(33)
    return BreakDuration(auto_return=auto_return, duration_pts=duration)


def _parse_splice_insert(br: BitReader) -> SpliceInsert:
    event_id = br.read(32)
    cancelled = bool(br.read(1))
    br.read(7)  # reserved

    si = SpliceInsert(event_id=event_id, cancelled=cancelled)
    if cancelled:
        return si

    si.out_of_network = bool(br.read(1))
    si.program_splice = bool(br.read(1))
    duration_flag = bool(br.read(1))
    si.splice_immediate = bool(br.read(1))
    br.read(4)  # reserved

    if si.program_splice and not si.splice_immediate:
        si.splice_time = _parse_splice_time(br)

    if not si.program_splice:
        count = br.read(8)
        for _ in range(count):
            br.read(8)  # component_tag
            if not si.splice_immediate:
                _parse_splice_time(br)

    if duration_flag:
        si.break_duration = _parse_break_duration(br)

    si.unique_program_id = br.read(16)
    si.avail_num = br.read(8)
    si.avails_expected = br.read(8)
    return si


def _parse_scte35_section(data: bytes, pid: int, program: int,
                           packet_num: int, packet_pts: Optional[int]) -> Optional[SCTE35Event]:
    if len(data) < 15 or data[0] != 0xFC:
        return None

    br = BitReader(data)
    br.read(8)   # table_id
    br.read(1)   # section_syntax_indicator
    br.read(1)   # private_indicator
    br.read(2)   # reserved
    section_length = br.read(12)

    if len(data) < 3 + section_length:
        return None

    if br.read(8) != 0:  # protocol_version
        return None

    encrypted = bool(br.read(1))
    br.read(6)   # encryption_algorithm
    pts_adjustment = br.read(33)
    br.read(8)   # cw_index
    br.read(12)  # tier
    br.read(12)  # splice_command_length
    command_type = br.read(8)

    names = {
        0x00: "splice_null",
        0x04: "splice_schedule",
        0x05: "splice_insert",
        0x06: "time_signal",
        0x07: "bandwidth_reservation",
        0xFF: "private_command",
    }

    event = SCTE35Event(
        pid=pid,
        program=program,
        packet_num=packet_num,
        pts_adjustment=pts_adjustment,
        command_type=command_type,
        command_name=names.get(command_type, f"unknown_0x{command_type:02X}"),
        packet_pts=packet_pts,
        raw_hex=data[:3 + section_length].hex(),
    )

    if command_type == 0x05 and not encrypted:
        try:
            event.splice_insert = _parse_splice_insert(br)
        except Exception:
            pass

    return event


# ── TS parser ─────────────────────────────────────────────────────────────────

class TSParser:
    def __init__(self):
        self.pmt_pids: set = set()
        self.scte35_pids: set = set()
        self.es_pids: set = set()          # video/audio PIDs for PTS tracking
        self._section_bufs: dict = {}
        self.events: List[SCTE35Event] = []
        self.packet_count: int = 0
        self._pat_done = False
        self.pcr_pid: Optional[int] = None
        self.first_pcr: Optional[int] = None
        self.last_pcr: Optional[int] = None
        self.current_pts: Optional[int] = None   # most recent PTS from any ES PID
        self._pid_to_program: Dict[int, int] = {}  # SCTE-35 pid -> program number

    def parse_file(self, path: str) -> None:
        with open(path, "rb") as f:
            probe = f.read(5)
            f.seek(0)
            if len(probe) < 5:
                return
            if probe[0] == SYNC_BYTE:
                prefix = 0
            elif probe[4] == SYNC_BYTE:
                prefix = 4   # M2TS: 4-byte timestamp prefix
            else:
                prefix = 0

            while True:
                if prefix:
                    f.read(prefix)
                raw = f.read(TS_PACKET_SIZE)
                if len(raw) < TS_PACKET_SIZE:
                    break
                if raw[0] != SYNC_BYTE:
                    continue
                self._process_packet(raw)
                self.packet_count += 1

    def _process_packet(self, pkt: bytes) -> None:
        pid = ((pkt[1] & 0x1F) << 8) | pkt[2]
        pusi = bool((pkt[1] >> 6) & 1)
        afc = (pkt[3] >> 4) & 0x03

        # PCR tracking
        if self.pcr_pid is not None and pid == self.pcr_pid:
            pcr = _extract_pcr_base(pkt)
            if pcr is not None:
                if self.first_pcr is None:
                    self.first_pcr = pcr
                self.last_pcr = pcr

        payload_start = 4
        if afc in (2, 3):
            payload_start = 5 + pkt[4]

        if afc not in (1, 3) or payload_start >= TS_PACKET_SIZE:
            return

        payload = pkt[payload_start:]

        if pid == PAT_PID:
            self._parse_pat(payload, pusi)
        elif pid in self.pmt_pids:
            self._parse_pmt(payload, pusi)
        elif pid in self.es_pids and pusi:
            # Extract PTS from PES header to track current stream time
            pts = _extract_pes_pts(payload)
            if pts is not None:
                self.current_pts = pts
        elif pid in self.scte35_pids:
            self._handle_scte35_payload(payload, pusi, pid)

    def _parse_pat(self, payload: bytes, pusi: bool) -> None:
        if self._pat_done:
            return
        if pusi:
            payload = payload[1 + payload[0]:]
        if len(payload) < 8 or payload[0] != 0x00:
            return

        section_length = ((payload[1] & 0x0F) << 8) | payload[2]
        end = min(3 + section_length - 4, len(payload))
        i = 8
        while i + 3 < end:
            prog = (payload[i] << 8) | payload[i + 1]
            pmt_pid = ((payload[i + 2] & 0x1F) << 8) | payload[i + 3]
            if prog != 0:
                self.pmt_pids.add(pmt_pid)
            i += 4
        self._pat_done = True

    def _parse_pmt(self, payload: bytes, pusi: bool) -> None:
        if pusi:
            payload = payload[1 + payload[0]:]
        if len(payload) < 12 or payload[0] != 0x02:
            return

        program_num = (payload[3] << 8) | payload[4]

        # PCR PID
        if self.pcr_pid is None and len(payload) >= 10:
            self.pcr_pid = ((payload[8] & 0x1F) << 8) | payload[9]

        section_length = ((payload[1] & 0x0F) << 8) | payload[2]
        prog_info_len = ((payload[10] & 0x0F) << 8) | payload[11]
        end = min(3 + section_length - 4, len(payload))
        i = 12 + prog_info_len

        while i + 4 < end:
            stream_type = payload[i]
            elem_pid = ((payload[i + 1] & 0x1F) << 8) | payload[i + 2]
            es_info_len = ((payload[i + 3] & 0x0F) << 8) | payload[i + 4]

            if stream_type == SCTE35_STREAM_TYPE:
                self.scte35_pids.add(elem_pid)
                self._pid_to_program[elem_pid] = program_num
            elif stream_type in PES_STREAM_TYPES:
                self.es_pids.add(elem_pid)

            i += 5 + es_info_len

    def _handle_scte35_payload(self, payload: bytes, pusi: bool, pid: int) -> None:
        if pusi:
            pointer = payload[0] if payload else 0
            payload = payload[1 + pointer:]
            self._section_bufs[pid] = bytearray(payload)
        else:
            if pid not in self._section_bufs:
                return
            self._section_bufs[pid].extend(payload)

        buf = bytes(self._section_bufs.get(pid, b""))
        if not buf:
            return

        program = self._pid_to_program.get(pid, 0)
        ev = _parse_scte35_section(buf, pid, program, self.packet_count, self.current_pts)
        if ev:
            self.events.append(ev)
            del self._section_bufs[pid]


# ── Report ────────────────────────────────────────────────────────────────────

def _sep(char="-", width=72):
    print(char * width)


def print_report(filepath: str, parser: TSParser) -> None:
    first_pcr = parser.first_pcr

    duration_str = "unknown"
    if first_pcr is not None and parser.last_pcr is not None:
        dur = pts_to_seconds((parser.last_pcr - first_pcr) & (PTS_MAX - 1))
        duration_str = format_seconds(dur)

    print()
    print(f"SCTE-35 Analysis: {Path(filepath).name}")
    _sep("=")
    print(f"  Total TS packets : {parser.packet_count:,}")
    print(f"  Stream duration  : {duration_str}")
    print(f"  PMT PID(s)       : {', '.join(f'0x{p:04X}' for p in sorted(parser.pmt_pids)) or 'none'}")
    if parser.pcr_pid is not None:
        print(f"  PCR PID          : 0x{parser.pcr_pid:04X}")
    print(f"  SCTE-35 PID(s)   : {', '.join(f'0x{p:04X}' for p in sorted(parser.scte35_pids)) or 'none'}")
    print(f"  SCTE-35 events   : {len(parser.events)}")

    if not parser.events:
        print("\n  No SCTE-35 events found.")
        return

    inserts = [e for e in parser.events if e.splice_insert is not None]
    other   = [e for e in parser.events if e.splice_insert is None]

    if inserts:
        print()
        print("SPLICE INSERT Events")
        _sep()
        col = "Stream Time" if first_pcr is not None else "Abs PTS"
        print(f"  {'Pkt#':>8}  {'PID':>6}  {'Prog':>4}  {'Event ID':>12}  "
              f"{'Type':<7}  {col+' (insert)':<16}  {col+' (splice)':<16}  "
              f"{'Lead':>8}  Duration")
        _sep()

        for ev in inserts:
            si = ev.splice_insert

            # Insertion time: when the SCTE-35 packet arrived (from nearest video/audio PTS)
            if ev.packet_pts is not None and first_pcr is not None:
                ins_str = format_seconds(relative_seconds(ev.packet_pts, 0, first_pcr))
            elif ev.packet_pts is not None:
                ins_str = format_pts(ev.packet_pts)
            else:
                ins_str = "—"

            if si.cancelled:
                type_str   = "CANCEL"
                splice_str = "—"
                lead_str   = ""
                dur_str    = ""
            elif si.out_of_network:
                type_str = "OUT"
                splice_str = si.splice_time.format(ev.pts_adjustment, first_pcr) if si.splice_time else "immediate"
                dur_str    = str(si.break_duration) if si.break_duration else "—"
                lead_str   = _lead(ev, first_pcr)
            else:
                type_str   = "IN"
                splice_str = si.splice_time.format(ev.pts_adjustment, first_pcr) if si.splice_time else "immediate"
                dur_str    = ""
                lead_str   = _lead(ev, first_pcr)

            print(f"  {ev.packet_num:>8,}  {ev.pid:>6}  {ev.program:>4}  "
                  f"0x{si.event_id:08X}  {type_str:<7}  {ins_str:<16}  "
                  f"{splice_str:<16}  {lead_str:>8}  {dur_str}")

        _sep()
        outs    = sum(1 for e in inserts if not e.splice_insert.cancelled and     e.splice_insert.out_of_network)
        ins_cnt = sum(1 for e in inserts if not e.splice_insert.cancelled and not e.splice_insert.out_of_network)
        cancels = sum(1 for e in inserts if e.splice_insert.cancelled)
        print(f"  Splice OUT (ad start) : {outs}")
        print(f"  Splice IN  (ad end)   : {ins_cnt}")
        print(f"  Cancelled             : {cancels}")

    # Ad break summary
    out_events = [e for e in inserts if e.splice_insert and
                  not e.splice_insert.cancelled and e.splice_insert.out_of_network]
    in_events  = [e for e in inserts if e.splice_insert and
                  not e.splice_insert.cancelled and not e.splice_insert.out_of_network]

    if out_events:
        print()
        print("Ad Break Summary")
        _sep()
        for out_ev in out_events:
            si = out_ev.splice_insert

            ins_str    = _ins_time(out_ev, first_pcr)
            splice_str = si.splice_time.format(out_ev.pts_adjustment, first_pcr) if si.splice_time else "immediate"
            lead_str   = _lead(out_ev, first_pcr)
            dur_str    = str(si.break_duration) if si.break_duration else "unknown"

            matched_in = next((e for e in in_events
                               if e.splice_insert.event_id == si.event_id), None)
            if matched_in and matched_in.splice_insert.splice_time:
                end_str = matched_in.splice_insert.splice_time.format(
                    matched_in.pts_adjustment, first_pcr)
            else:
                end_str = "—"

            print(f"  Event 0x{si.event_id:08X}  (program {out_ev.program})")
            print(f"    Trigger inserted at : {ins_str}  (PTS of nearest A/V packet)")
            print(f"    Command executes at : {splice_str}  (splice_time PTS)")
            print(f"    Lead time           : {lead_str}")
            print(f"    Break end           : {end_str}")
            print(f"    Break duration      : {dur_str}")
            if si.unique_program_id:
                print(f"    Unique program ID   : {si.unique_program_id}")
            if si.avails_expected:
                print(f"    Avail               : {si.avail_num} of {si.avails_expected}")
            print()

    if other:
        print("Other SCTE-35 Commands")
        _sep()
        for ev in other:
            print(f"  Pkt {ev.packet_num:,}  PID=0x{ev.pid:04X}  prog={ev.program}  command={ev.command_name}")
        print()


def _ins_time(ev: SCTE35Event, first_pcr: Optional[int]) -> str:
    if ev.packet_pts is None:
        return "—"
    if first_pcr is not None:
        return format_seconds(relative_seconds(ev.packet_pts, 0, first_pcr))
    return format_pts(ev.packet_pts)


def _lead(ev: SCTE35Event, first_pcr: Optional[int]) -> str:
    """Seconds between when the SCTE-35 arrived and when the splice executes."""
    si = ev.splice_insert
    if si is None or si.pts is None or ev.packet_pts is None:
        return "—"
    diff = pts_to_seconds(
        ((si.pts + ev.pts_adjustment) - ev.packet_pts) & (PTS_MAX - 1)
    )
    return f"{diff:.3f}s"


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <file.ts> [file2.ts ...]")
        sys.exit(1)

    for filepath in sys.argv[1:]:
        p = Path(filepath)
        if not p.exists():
            print(f"Error: file not found: {filepath}", file=sys.stderr)
            continue
        if not p.is_file():
            print(f"Error: not a file: {filepath}", file=sys.stderr)
            continue

        parser = TSParser()
        try:
            parser.parse_file(filepath)
        except Exception as e:
            print(f"Error parsing {filepath}: {e}", file=sys.stderr)
            import traceback
            traceback.print_exc()
            continue

        print_report(filepath, parser)


if __name__ == "__main__":
    main()
