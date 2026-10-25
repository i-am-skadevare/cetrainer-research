
import argparse
import hashlib
import zlib
from pathlib import Path


KEYS = [
    b"\x2A\xAD\x2B\x41",       # Modified CE 6.4, 32-bit
    b"\x65\x42\x17\x43\x65",   # Modified CE 6.5, 64-bit
    b"\x65\x42\x17\x43",
]


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview(data: bytes, count: int = 32) -> str:
    return data[:count].hex(" ")


def looks_like_xml(data: bytes) -> bool:
    data = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    return (
        data.startswith(b"<?xml")
        or data.startswith(b"<CheatTable")
        or data.startswith(b"< cheat")
    )


def round_xor_const(data: bytearray, key: int) -> None:
    for i in range(len(data)):
        data[i] ^= key
        key = (key + 1) & 0xFF


def transform(data: bytes) -> bytearray:
    """Apply the two initial XOR passes from the supplied algorithm."""
    result = bytearray(data)

    for i in range(2, len(result)):
        result[i] ^= result[i - 2]

    for i in range(len(result) - 2, -1, -1):
        result[i] ^= result[i + 1]

    return result


def decompress_candidates(data: bytes):
    """Try common DEFLATE container modes; report each failure."""
    modes = [
        ("raw-deflate", -zlib.MAX_WBITS),
        ("zlib", zlib.MAX_WBITS),
        ("gzip", zlib.MAX_WBITS | 16),
    ]

    for name, window_bits in modes:
        try:
            decoded = zlib.decompress(data, window_bits)
            yield name, decoded, None
        except zlib.error as exc:
            yield name, None, str(exc)


def decode(data: bytes):
    """
    Return (decoded_bytes, description).
    Does not modify the source file.
    """
    if looks_like_xml(data):
        print("[+] Input already looks like XML; no decryption needed.")
        return data, "original-xml"

    print("[*] Protected/non-XML input suspected.")
    print(f"[*] Input length: {len(data):,} bytes")
    print(f"[*] Input SHA-256: {sha256(data)}")
    print(f"[*] Input prefix: {preview(data)}")

    transformed = bytes(transform(data))
    print(f"[*] After initial XOR passes: {preview(transformed)}")

    attempts = 0

    for key in KEYS:
        key_text = ":".join(f"{b:02X}" for b in key)
        print(f"\n[*] Trying key: {key_text}")

        candidate = bytearray(transformed)
        for value in key:
            round_xor_const(candidate, value)

        candidate = bytes(candidate)
        print(f"    Candidate prefix: {preview(candidate)}")

        # The supplied algorithm has a special "CHEAT" container case.
        if candidate.startswith(b"CHEAT"):
            print("    [+] CHEAT marker found.")
            payloads = [
                ("CHEAT payload", candidate[5:]),
            ]
        else:
            payloads = [
                ("full candidate", candidate),
            ]

        for payload_name, payload in payloads:
            for mode, decoded, error in decompress_candidates(payload):
                attempts += 1

                if decoded is None:
                    print(f"    [-] {payload_name} / {mode}: {error}")
                    continue

                print(
                    f"    [+] Decompression succeeded: {payload_name} / "
                    f"{mode}, {len(decoded):,} bytes"
                )
                print(f"        Prefix: {preview(decoded)}")
                print(f"        SHA-256: {sha256(decoded)}")

                # The original snippet strips 4 bytes only in the CHEAT
                # branch. Keep both versions if the prefix is ambiguous.
                if candidate.startswith(b"CHEAT") and len(decoded) >= 4:
                    stripped = decoded[4:]
                    if looks_like_xml(stripped):
                        print("    [+] XML detected after removing 4-byte prefix.")
                        return stripped, f"{key_text}-{mode}-cheat-prefix4"

                if looks_like_xml(decoded):
                    print("    [+] Output looks like a Cheat Engine XML table.")
                    return decoded, f"{key_text}-{mode}"

                # A successful decompression is useful evidence even if
                # the result is not recognized as XML.
                return decoded, f"{key_text}-{mode}-unverified"

    raise RuntimeError(
        f"No candidate decompressed successfully ({attempts} attempts). "
        "The file may use another key, another transform, or a different format."
    )


def main():
    parser = argparse.ArgumentParser(
        description="Diagnose and attempt to decode a CETRAINER file."
    )
    parser.add_argument("input", help="Path to the .CETRAINER file")
    parser.add_argument(
        "-o", "--output",
        help="Output path (default: <input>.decoded.bin)",
    )
    args = parser.parse_args()

    source = Path(args.input)
    if not source.is_file():
        parser.error(f"Input file not found: {source}")

    original = source.read_bytes()
    output = Path(args.output) if args.output else Path(
        str(source) + ".decoded.bin"
    )

    try:
        decoded, method = decode(original)
    except Exception as exc:
        print(f"\n[!] Decode failed: {type(exc).__name__}: {exc}")
        print("[!] Original file was not changed.")
        raise SystemExit(1)

    # Use .xml only when the output actually looks like XML.
    if args.output is None and looks_like_xml(decoded):
        output = Path(str(source) + ".decoded.xml")

    output.write_bytes(decoded)

    print("\n[+] Finished.")
    print(f"    Method: {method}")
    print(f"    Output: {output.resolve()}")
    print(f"    Size: {len(decoded):,} bytes")
    print(f"    SHA-256: {sha256(decoded)}")
    print(f"    XML-like: {looks_like_xml(decoded)}")
    print(f"    Prefix: {preview(decoded)}")


if __name__ == "__main__":
    main()
