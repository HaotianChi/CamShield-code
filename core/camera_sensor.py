                     
"""
AU-aware sensors for CamShield.

This replaces SimulatedSensor with real encoded media input.

Two modes:
1. FileH264AUSensor:
   - offline VM test
   - input: sample.h264
   - output: m_i = grouped AU bytes

2. FFmpegH264LiveSensor:
   - real camera / live test
   - input: USB camera through ffmpeg
   - output: m_i = grouped AU bytes
"""

from __future__ import annotations

import os
import subprocess
import time
from dataclasses import dataclass
from typing import Optional

from core.camera import SensorCaptureRequest, SensorSegmentData
from core.h264_au import (
    AnnexBNALUStream,
    H264AUBuilder,
    group_aus,
    iter_aus_from_annexb,
)
from core.protocol_defaults import DEFAULT_CAPTURE_FPS, default_aus_per_segment


@dataclass
class FileH264AUSensor:
    """
    Offline H.264 file sensor.

    It reads an Annex-B .h264 file, parses AU units, and returns one CamShield
    segment m_i per capture_segment() call.
    """

    h264_path: str
    aus_per_segment: int = default_aus_per_segment()
    loop: bool = False

    def __post_init__(self) -> None:
        if not os.path.exists(self.h264_path):
            raise FileNotFoundError(self.h264_path)

        with open(self.h264_path, "rb") as f:
            data = f.read()

        aus = iter_aus_from_annexb(data)
        if not aus:
            raise RuntimeError("No AU found. Check whether the file is H.264 Annex-B.")

        self._segments = group_aus(aus, self.aus_per_segment)
        self._idx = 0

        print(f"[AU Sensor] Loaded {len(aus)} AUs")
        print(f"[AU Sensor] Built {len(self._segments)} CamShield segments")
        print(f"[AU Sensor] aus_per_segment={self.aus_per_segment}")

    def capture_segment(self, request: SensorCaptureRequest) -> SensorSegmentData:
        sid = request.sid or f"{request.camera_id}_seg_{request.seq:06d}"

                                                 
        if request.raw_payload is not None:
            payload = request.raw_payload
        else:
            if self._idx >= len(self._segments):
                if self.loop:
                    self._idx = 0
                else:
                    raise EOFError("No more H.264 AU segments available")

            payload = self._segments[self._idx]
            self._idx += 1

        return SensorSegmentData(
            cid=request.camera_id,
            sid=sid,
            seq=request.seq,
            timestamp=request.timestamp,
            raw_payload=payload,
        )


@dataclass
class FFmpegH264LiveSensor:
    """
    Live H.264 sensor backed by ffmpeg.

    It runs ffmpeg, reads Annex-B H.264 from stdout, parses NALU/AU,
    groups several AUs into one CamShield segment m_i, and returns it.

    For Raspberry Pi USB camera:
        device="/dev/video0", testsrc=False

    For VM live simulation:
        testsrc=True
    """

    device: str = "/dev/video0"
    fps: int = DEFAULT_CAPTURE_FPS
    size: str = "640x360"
    aus_per_segment: int = default_aus_per_segment()
    ffmpeg_bin: str = "ffmpeg"
    testsrc: bool = False

    def __post_init__(self) -> None:
        self._proc: Optional[subprocess.Popen] = None
        self._nalu_stream = AnnexBNALUStream()
        self._au_builder = H264AUBuilder()
        self._pending_aus: list[bytes] = []

    def _build_ffmpeg_cmd(self) -> list[str]:
        x264_params = f"keyint={self.fps}:min-keyint={self.fps}:scenecut=0:slices=1"

        if self.testsrc:
            input_args = [
                "-re",
                "-f", "lavfi",
                "-i", f"testsrc=size={self.size}:rate={self.fps}",
            ]
        else:
            input_args = [
                "-f", "v4l2",
                "-framerate", str(self.fps),
                "-video_size", self.size,
                "-i", self.device,
            ]

        return [
            self.ffmpeg_bin,
            "-hide_banner",
            "-loglevel", "error",
            *input_args,
            "-an",
            "-c:v", "libx264",
            "-preset", "ultrafast",
            "-tune", "zerolatency",
            "-profile:v", "baseline",
            "-x264-params", x264_params,
            "-pix_fmt", "yuv420p",
            "-f", "h264",
            "-",
        ]

    def start(self) -> None:
        if self._proc is not None:
            return

        cmd = self._build_ffmpeg_cmd()
        print("[FFmpeg Sensor] Starting ffmpeg:")
        print(" ".join(cmd))

        self._proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            bufsize=0,
        )

        if self._proc.stdout is None:
            raise RuntimeError("ffmpeg stdout is not available")

    def close(self) -> None:
        if self._proc is None:
            return

        self._proc.terminate()
        try:
            self._proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            self._proc.kill()

        self._proc = None

    def _read_more_aus(self) -> None:
        self.start()

        assert self._proc is not None
        assert self._proc.stdout is not None

        chunk = self._proc.stdout.read(4096)
        if not chunk:
            err = b""
            if self._proc.stderr is not None:
                try:
                    err = self._proc.stderr.read(4096)
                except Exception:
                    pass
            raise RuntimeError(f"ffmpeg produced no data. stderr={err.decode(errors='ignore')}")

        nalus = self._nalu_stream.feed(chunk)
        aus = self._au_builder.feed_nalus(nalus)
        self._pending_aus.extend(aus)

    def _read_segment_payload(self) -> bytes:
        while len(self._pending_aus) < self.aus_per_segment:
            self._read_more_aus()

        selected = self._pending_aus[:self.aus_per_segment]
        self._pending_aus = self._pending_aus[self.aus_per_segment:]
        return b"".join(selected)

    def capture_segment(self, request: SensorCaptureRequest) -> SensorSegmentData:
        sid = request.sid or f"{request.camera_id}_seg_{request.seq:06d}"

        if request.raw_payload is not None:
            payload = request.raw_payload
        else:
            payload = self._read_segment_payload()

        return SensorSegmentData(
            cid=request.camera_id,
            sid=sid,
            seq=request.seq,
            timestamp=request.timestamp or int(time.time()),
            raw_payload=payload,
        )
