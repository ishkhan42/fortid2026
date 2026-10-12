#!/usr/bin/env python3
"""Render one PMAF stream over a local RGB starting image.

PMAF v1 uses a 40-byte header followed by 8-byte keyed operations. The native
core maintains 4-connected color components incrementally so repeated fills do
not rescan the whole image. The C source is compiled to the system temporary
directory on first use; no network or project-specific files are accessed.
"""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import io
import os
from pathlib import Path
import subprocess
import struct
import tempfile
from typing import Any

import numpy as np
from PIL import Image

_MAGIC = b"PMAF\x03\r\n\x1a"
_HEADER = struct.Struct("<IIQQII")
_ENGINE: Any = None


def _load_engine() -> Any:
    global _ENGINE
    if _ENGINE is not None:
        return _ENGINE

    source = Path(__file__).with_name("pmaf_renderer.c")
    source_bytes = source.read_bytes()
    digest = hashlib.sha256(source_bytes).hexdigest()[:20]
    library_path = Path(tempfile.gettempdir()) / f"pmaf-render-{digest}.so"
    if not library_path.exists():
        fd, temporary_name = tempfile.mkstemp(
            prefix="pmaf-render-", suffix=".so", dir=tempfile.gettempdir()
        )
        os.close(fd)
        try:
            subprocess.run(
                [
                    os.environ.get("CC", "cc"),
                    "-O3",
                    "-std=c11",
                    "-fPIC",
                    "-shared",
                    str(source),
                    "-o",
                    temporary_name,
                ],
                check=True,
                capture_output=True,
                text=True,
            )
            os.replace(temporary_name, library_path)
        finally:
            if os.path.exists(temporary_name):
                os.unlink(temporary_name)

    engine = ctypes.CDLL(str(library_path))
    engine.pmaf_render.argtypes = [
        ctypes.POINTER(ctypes.c_uint32),
        ctypes.c_uint32,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint8),
        ctypes.c_uint64,
        ctypes.c_uint64,
        ctypes.c_uint32,
        ctypes.POINTER(ctypes.c_uint64),
    ]
    engine.pmaf_render.restype = ctypes.c_int
    _ENGINE = engine
    return engine


def _open_start_png(start_png: Any) -> np.ndarray:
    if isinstance(start_png, (str, os.PathLike)):
        with Image.open(start_png) as image:
            return np.asarray(image.convert("RGB"), dtype=np.uint8)
    if isinstance(start_png, Image.Image):
        return np.asarray(start_png.convert("RGB"), dtype=np.uint8)
    with Image.open(io.BytesIO(bytes(start_png))) as image:
        return np.asarray(image.convert("RGB"), dtype=np.uint8)


def render(
    start_png: str | os.PathLike | Image.Image | bytes,
    pmaf_bytes: bytes | bytearray | memoryview,
) -> np.ndarray:
    """Return an ``(height, width, 3)`` uint8 RGB array for one PMAF stream."""
    if not isinstance(pmaf_bytes, bytes):
        pmaf_bytes = bytes(pmaf_bytes)
    if len(pmaf_bytes) < 40 or pmaf_bytes[:8] != _MAGIC:
        raise ValueError("invalid PMAF magic or truncated header")

    width, height, operation_count, seed, mode, reserved = _HEADER.unpack_from(
        pmaf_bytes, 8
    )
    if width == 0 or height == 0 or width * height > 0xFFFFFF:
        raise ValueError("invalid PMAF dimensions")
    if reserved != 0:
        raise ValueError("unsupported nonzero PMAF reserved field")
    if len(pmaf_bytes) != 40 + operation_count * 8:
        raise ValueError("PMAF operation count does not match stream length")

    rgb = _open_start_png(start_png)
    if rgb.shape != (height, width, 3):
        raise ValueError(
            f"start image is {rgb.shape[1]}x{rgb.shape[0]}, "
            f"PMAF expects {width}x{height}"
        )
    pixels = np.ascontiguousarray(
        (rgb[:, :, 0].astype(np.uint32) << 16)
        | (rgb[:, :, 1].astype(np.uint32) << 8)
        | rgb[:, :, 2].astype(np.uint32)
    ).reshape(-1)

    # PyBytes_AsString exposes the immutable operation payload without copying it.
    get_bytes = ctypes.pythonapi.PyBytes_AsString
    get_bytes.argtypes = [ctypes.py_object]
    get_bytes.restype = ctypes.c_void_p
    stream_address = int(get_bytes(pmaf_bytes)) + 40
    stream = ctypes.cast(stream_address, ctypes.POINTER(ctypes.c_uint8))
    bad_op = ctypes.c_uint64(0)
    status = _load_engine().pmaf_render(
        pixels.ctypes.data_as(ctypes.POINTER(ctypes.c_uint32)),
        width,
        height,
        stream,
        operation_count,
        seed,
        mode,
        ctypes.byref(bad_op),
    )
    if status == 1:
        raise ValueError(f"invalid PMAF operation checksum at record {bad_op.value}")
    if status == 2:
        raise ValueError(f"PMAF pixel index out of range at record {bad_op.value}")
    if status == 3:
        raise ValueError("PMAF dimensions exceed the renderer's 24-bit pixel index")
    if status == 4:
        raise MemoryError("unable to allocate PMAF renderer state")
    if status != 0:
        raise RuntimeError(f"PMAF renderer failed with status {status}")

    channels = pixels.reshape(height, width)
    result = np.empty((height, width, 3), dtype=np.uint8)
    result[:, :, 0] = (channels >> 16) & 0xFF
    result[:, :, 1] = (channels >> 8) & 0xFF
    result[:, :, 2] = channels & 0xFF
    return result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("start_png", type=Path, help="local starting PNG image")
    parser.add_argument("stream", type=Path, help="local PMAF stream file")
    parser.add_argument("output_png", type=Path, help="destination PNG image")
    args = parser.parse_args()

    image = render(args.start_png, args.stream.read_bytes())
    Image.fromarray(image, mode="RGB").save(args.output_png)


if __name__ == "__main__":
    main()
