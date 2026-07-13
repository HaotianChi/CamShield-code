"""
H.264 Annex-B NALU/AU parser for CamShield camera ingest.

Purpose:
    H.264 Annex-B byte stream
        -> NALU
        -> AU
        -> AU groups
        -> CamShield segment m_i

Encoder assumption:
    x264 with slices=1 and baseline profile, so one VCL NALU usually maps to
    one encoded frame / AU.

Supported sources:
    - sample H.264 files
    - ffmpeg live H.264 stdout
    - USB camera capture pipelines

This is a focused parser for CamShield segmenting, not a full H.264 stack.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable


START_CODE_3 = b"\x00\x00\x01"
START_CODE_4 = b"\x00\x00\x00\x01"

                      
NAL_TYPE_NON_IDR = 1
NAL_TYPE_IDR = 5
NAL_TYPE_SEI = 6
NAL_TYPE_SPS = 7
NAL_TYPE_PPS = 8
NAL_TYPE_AUD = 9

VCL_NAL_TYPES = {1, 2, 3, 4, 5}


def _find_start_code(buf: bytes | bytearray, start: int = 0) -> tuple[int, int] | None:
    """
    Return (index, length) of next Annex-B start code.
    Supports 00 00 01 and 00 00 00 01.
    """
    i3 = bytes(buf).find(START_CODE_3, start)
    i4 = bytes(buf).find(START_CODE_4, start)

    candidates: list[tuple[int, int]] = []
    if i3 != -1:
        candidates.append((i3, 3))
    if i4 != -1:
        candidates.append((i4, 4))

    if not candidates:
        return None

                                                                   
    candidates.sort(key=lambda x: (x[0], -x[1]))
    return candidates[0]


def strip_start_code(nalu: bytes) -> bytes:
    if nalu.startswith(START_CODE_4):
        return nalu[4:]
    if nalu.startswith(START_CODE_3):
        return nalu[3:]
    return nalu


def nalu_type(nalu: bytes) -> int:
    payload = strip_start_code(nalu)
    if not payload:
        raise ValueError("empty NALU")
    return payload[0] & 0x1F


def split_annexb_nalus(data: bytes) -> list[bytes]:
    """
    Split a full Annex-B file into NALUs.
    Each returned NALU keeps its start code.
    """
    parser = AnnexBNALUStream()
    nalus = parser.feed(data)
    last = parser.flush()
    if last is not None:
        nalus.append(last)
    return nalus


@dataclass
class AnnexBNALUStream:
    """
    Streaming Annex-B NALU extractor.

    Feed arbitrary chunks from ffmpeg stdout.
    It returns complete NALUs and keeps the last incomplete NALU in the buffer.
    """

    buffer: bytearray = bytearray()

    def feed(self, data: bytes) -> list[bytes]:
        if not data:
            return []

        self.buffer.extend(data)
        out: list[bytes] = []

        first = _find_start_code(self.buffer, 0)
        if first is None:
                                                                             
            if len(self.buffer) > 8:
                del self.buffer[:-8]
            return out

        first_idx, first_len = first
        if first_idx > 0:
            del self.buffer[:first_idx]

        pos = 0
        while True:
            cur = _find_start_code(self.buffer, pos)
            if cur is None:
                break

            cur_idx, cur_len = cur
            nxt = _find_start_code(self.buffer, cur_idx + cur_len)
            if nxt is None:
                                                   
                if cur_idx > 0:
                    del self.buffer[:cur_idx]
                break

            next_idx, _ = nxt
            nalu = bytes(self.buffer[cur_idx:next_idx])
            if strip_start_code(nalu):
                out.append(nalu)
            pos = next_idx

            if pos > 0:
                del self.buffer[:pos]
                pos = 0

        return out

    def flush(self) -> bytes | None:
        first = _find_start_code(self.buffer, 0)
        if first is None:
            self.buffer.clear()
            return None

        first_idx, _ = first
        if first_idx > 0:
            del self.buffer[:first_idx]

        if not self.buffer:
            return None

        nalu = bytes(self.buffer)
        self.buffer.clear()

        if strip_start_code(nalu):
            return nalu
        return None


@dataclass
class H264AUBuilder:
    """
    Simplified AU builder.

    With x264 slices=1, each VCL NALU is treated as one AU.
    Pending SPS/PPS/SEI/AUD NALUs are attached to the next VCL NALU.
    """

    pending_prefix_nalus: list[bytes] | None = None

    def __post_init__(self) -> None:
        if self.pending_prefix_nalus is None:
            self.pending_prefix_nalus = []

    def feed_nalu(self, nalu: bytes) -> list[bytes]:
        typ = nalu_type(nalu)

        if typ in VCL_NAL_TYPES:
            au_nalus = self.pending_prefix_nalus + [nalu]
            self.pending_prefix_nalus = []
            return [b"".join(au_nalus)]

        self.pending_prefix_nalus.append(nalu)
        return []

    def feed_nalus(self, nalus: Iterable[bytes]) -> list[bytes]:
        aus: list[bytes] = []
        for nalu in nalus:
            aus.extend(self.feed_nalu(nalu))
        return aus


def iter_aus_from_annexb(data: bytes) -> list[bytes]:
    nalus = split_annexb_nalus(data)
    builder = H264AUBuilder()
    return builder.feed_nalus(nalus)


def group_aus(aus: list[bytes], aus_per_segment: int) -> list[bytes]:
    if aus_per_segment <= 0:
        raise ValueError("aus_per_segment must be positive")

    segments: list[bytes] = []
    for i in range(0, len(aus), aus_per_segment):
        group = aus[i:i + aus_per_segment]
        if group:
            segments.append(b"".join(group))
    return segments
