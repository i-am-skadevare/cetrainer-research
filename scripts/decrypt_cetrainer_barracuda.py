#!/usr/bin/env python3
"""Diagnostic decoder for Barracuda / Cheat Engine .CETRAINER samples.

Features:
- Original two chained-XOR passes.
- Known incrementing-XOR keys 0xCB and 0xCF, plus 0xCE as a compatibility fallback.
- The specifically observed modified CE 6.7 wrapper:
  XOR key 0xCA with step +5 -> BRICKED\x00\x15\x00 -> raw DEFLATE ->
  4-byte little-endian XML size -> CheatTable XML.
- Diagnostics (input/output size, SHA-256, byte previews, tested profile,
  decompression failures) and a persistent log.
- Full XML parsing, decompression-size limit, no silent overwrite of source/results.
- Optional prefix-screened or exhaustive scan for unknown single-byte
  incrementing-XOR keys.

This is research code. The BRICKED variant was verified for one specific
Watch Dogs trainer sample; compatibility with other samples is not guaranteed.
The script treats trainer files as data and does not execute them.

Usage:
    python decrypt_cetrainer_barracuda.py
    python decrypt_cetrainer_barracuda.py sample.CETRAINER
    python decrypt_cetrainer_barracuda.py sample.CETRAINER -o decoded.xml
    python decrypt_cetrainer_barracuda.py sample.CETRAINER --deep-scan
    python decrypt_cetrainer_barracuda.py sample.CETRAINER --exhaustive-scan
"""
from __future__ import annotations

import argparse
import hashlib
import sys
import zlib
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Optional, Sequence

PROGRAM_NAME = "decrypt_cetrainer_barracuda.py"
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024
AUTO_SCAN_LIMIT = 128 * 1024
SCAN_PREFIX_BYTES = 16 * 1024
SCAN_PREFIX_OUTPUT_BYTES = 32 * 1024

# These one-byte incrementing-key profiles are independent fallbacks. The
# original Barracuda unpacker checks 0xCB and 0xCF; 0xCE is included as a
# common Cheat Engine profile for compatibility/diagnostics.
KNOWN_KEYS: Sequence[tuple[str, int]] = (
    ("Barracuda key 0xCB", 0xCB),
    ("Barracuda key 0xCF", 0xCF),
    ("Classic Cheat Engine key 0xCE fallback", 0xCE),
)
DEFLATE_MODES: Sequence[tuple[str, int]] = (
    ("raw-deflate", -zlib.MAX_WBITS),
    ("zlib", zlib.MAX_WBITS),
    ("gzip", zlib.MAX_WBITS | 16),
)
LOG_LINES: list[str] = []


def report(message: str = "") -> None:
    print(message, flush=True)
    LOG_LINES.append(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview(data: bytes, count: int = 32) -> str:
    return data[:count].hex(" ") or "<empty>"


def local_xml_name(tag: object) -> str:
    if not isinstance(tag, str):
        return ""
    return tag.rsplit("}", 1)[-1].split(":")[-1]


def valid_cheattable_xml(data: bytes) -> bool:
    """Only accept well-formed XML whose root element is CheatTable."""
    if not data:
        return False
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError, UnicodeError):
        return False
    return local_xml_name(root.tag).casefold() == "cheattable"


def looks_like_xml_text(data: bytes) -> bool:
    """Fast heuristic for diagnostics/key screening; not proof of valid XML."""
    sample = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n\x00")
    lowered = sample.lower()
    return (
        lowered.startswith(b"<?xml")
        or lowered.startswith(b"<cheattable")
        or b"<cheattable" in lowered
    )


def chained_xor_waves(data: bytes) -> bytes:
    """Apply the two chained XOR passes used by the source unpackers."""
    result = bytearray(data)
    for i in range(2, len(result)):
        result[i] ^= result[i - 2]
    for i in range(len(result) - 2, -1, -1):
        result[i] ^= result[i + 1]
    return bytes(result)


def xor_incrementing_key(data: bytes, initial_key: int, step: int = 1) -> bytes:
    """XOR each byte with a key that advances by `step` modulo 256."""
    result = bytearray(data)
    key = initial_key & 0xFF
    step &= 0xFF
    for i in range(len(result)):
        result[i] ^= key
        key = (key + step) & 0xFF
    return bytes(result)


def bounded_decompress(data: bytes, wbits: int) -> bytes:
    """Decompress with a size cap and require a complete stream."""
    decompressor = zlib.decompressobj(wbits)
    output = decompressor.decompress(data, MAX_DECOMPRESSED_BYTES + 1)
    if len(output) > MAX_DECOMPRESSED_BYTES or decompressor.unconsumed_tail:
        raise ValueError(
            f"decompressed output exceeds the {MAX_DECOMPRESSED_BYTES:,}-byte safety cap"
        )
    tail = decompressor.flush()
    if len(output) + len(tail) > MAX_DECOMPRESSED_BYTES:
        raise ValueError(
            f"decompressed output exceeds the {MAX_DECOMPRESSED_BYTES:,}-byte safety cap"
        )
    output += tail
    if not decompressor.eof:
        raise ValueError("incomplete DEFLATE stream")
    return output


def candidate_payloads(candidate: bytes) -> list[tuple[str, bytes]]:
    """Try common wrapper offsets without assuming every header is identical."""
    payloads: list[tuple[str, bytes]] = []
    seen: set[tuple[int, bytes]] = set()

    def add(label: str, payload: bytes) -> None:
        if not payload:
            return
        fingerprint = (len(payload), hashlib.sha1(payload[:64] + payload[-64:]).digest())
        if fingerprint not in seen:
            seen.add(fingerprint)
            payloads.append((label, payload))

    if candidate.startswith(b"CHEAT"):
        add("CHEAT payload offset 5", candidate[5:])
        if len(candidate) >= 9:
            add("CHEAT payload offset 9 (possible size field)", candidate[9:])
    else:
        add("whole candidate", candidate)
        if len(candidate) > 4:
            add("candidate after possible 4-byte prefix", candidate[4:])
    return payloads


def possible_outputs(inflated: bytes) -> list[tuple[str, bytes]]:
    """Yield the full inflate result and an indicated 4-byte-size payload."""
    outputs = [("full inflate output", inflated)]
    if len(inflated) >= 4:
        declared = int.from_bytes(inflated[:4], "little", signed=False)
        body = inflated[4:]
        if declared == len(body):
            outputs.insert(0, (f"strip matching 4-byte LE length ({declared})", body))
    return outputs


def try_candidate(
    candidate: bytes,
    label: str,
    *,
    quiet: bool = False,
) -> tuple[Optional[tuple[bytes, str]], Optional[tuple[bytes, str]]]:
    """Return (validated XML result, best unverified decompressed candidate)."""
    if valid_cheattable_xml(candidate):
        if not quiet:
            report(f"[+] Valid CheatTable XML found directly: {label}")
        return (candidate, label), None

    best_binary: Optional[tuple[bytes, str]] = None
    for payload_label, payload in candidate_payloads(candidate):
        for mode, wbits in DEFLATE_MODES:
            try:
                inflated = bounded_decompress(payload, wbits)
            except (zlib.error, ValueError) as exc:
                if not quiet:
                    report(f"[-] {label} / {payload_label} / {mode}: {exc}")
                continue

            description = f"{label} / {payload_label} / {mode}"
            if not quiet:
                report(f"[+] Decompression succeeded: {description} ({len(inflated):,} bytes)")
                report(f"    Inflated prefix: {preview(inflated)}")

            for output_label, output in possible_outputs(inflated):
                method = f"{description} / {output_label}"
                if valid_cheattable_xml(output):
                    if not quiet:
                        report(f"[+] Full XML parse passed: {method}")
                        report(f"    XML SHA-256: {sha256(output)}")
                    return (output, method), best_binary
                if best_binary is None or len(output) > len(best_binary[0]):
                    best_binary = (output, method)
                if not quiet:
                    report(f"[!] Output is not validated CheatTable XML ({output_label}).")
    return None, best_binary


def prefix_candidate_looks_plausible(candidate: bytes) -> bool:
    """Cheap 16 KiB candidate screen before full-file XOR/decompression work."""
    if not candidate:
        return False
    if candidate.startswith(b"CHEAT") or looks_like_xml_text(candidate):
        return True
    for payload_label, payload in candidate_payloads(candidate):
        del payload_label
        for _, wbits in DEFLATE_MODES:
            try:
                inflater = zlib.decompressobj(wbits)
                output = inflater.decompress(payload, SCAN_PREFIX_OUTPUT_BYTES)
            except (zlib.error, ValueError):
                continue
            if looks_like_xml_text(output):
                return True
    return False


def try_bricked_variant(chained: bytes) -> Optional[tuple[bytes, str]]:
    """Try the sample-specific BRICKED wrapper discovered for one CE 6.7 file."""
    candidate = xor_incrementing_key(chained, 0xCA, 5)
    signature = b"BRICKED\x00\x15\x00"
    if not candidate.startswith(signature):
        report("[*] BRICKED variant: signature not found with key 0xCA, step +5.")
        return None

    report("\n[+] BRICKED signature matched: key 0xCA, step +5; DEFLATE offset 10.")
    report(f"[*] Transformed prefix: {preview(candidate)}")
    try:
        inflated = bounded_decompress(candidate[len(signature):], -zlib.MAX_WBITS)
    except (zlib.error, ValueError) as exc:
        report(f"[-] BRICKED raw-DEFLATE decoding/validation failed: {exc}")
        return None

    report(f"[*] BRICKED raw-DEFLATE output: {len(inflated):,} bytes; prefix {preview(inflated)}")
    if len(inflated) < 4:
        report("[-] BRICKED output is too short for the 4-byte XML length field.")
        return None

    declared_size = int.from_bytes(inflated[:4], "little", signed=False)
    xml_data = inflated[4:]
    xml_ok = valid_cheattable_xml(xml_data)
    report(
        f"[*] BRICKED XML size field: declared={declared_size:,}; "
        f"actual={len(xml_data):,}; valid CheatTable XML={xml_ok}."
    )
    if declared_size != len(xml_data) or not xml_ok:
        report("[-] BRICKED candidate rejected because its length field or XML validation failed.")
        return None

    report(f"[+] BRICKED variant validated. XML SHA-256: {sha256(xml_data)}")
    return xml_data, "Barracuda modified CE 6.7 / BRICKED / key 0xCA step +5"


def decode(
    data: bytes,
    *,
    deep_scan: bool = False,
    exhaustive_scan: bool = False,
) -> tuple[bytes, str, bool]:
    """Decode data, returning (output bytes, method description, is_valid_xml)."""
    if not data:
        raise ValueError("The selected input file is empty.")

    report("[*] Barracuda decoder started")
    report(f"[*] Input size: {len(data):,} bytes")
    report(f"[*] Input SHA-256: {sha256(data)}")
    report(f"[*] Input prefix: {preview(data)}")

    if valid_cheattable_xml(data):
        report("[+] Input is already valid CheatTable XML; returning it unchanged.")
        return data, "input already valid CheatTable XML", True

    best_binary: Optional[tuple[bytes, str]] = None

    # Some files may be compressed without protection; check the input first.
    found, binary = try_candidate(data, "original bytes")
    if found:
        return found[0], found[1], True
    if binary and (best_binary is None or len(binary[0]) > len(best_binary[0])):
        best_binary = binary

    # First two chained XOR waves.
    chained = chained_xor_waves(data)
    report(f"\n[*] After two chained XOR waves: {preview(chained)}")
    found, binary = try_candidate(chained, "chain XOR waves only")
    if found:
        return found[0], found[1], True
    if binary and (best_binary is None or len(binary[0]) > len(best_binary[0])):
        best_binary = binary

    # The sample-specific modified CE 6.7 / BRICKED algorithm must be tested
    # before the conventional Barracuda keys.
    bricked = try_bricked_variant(chained)
    if bricked:
        return bricked[0], bricked[1], True

    # Known incrementing-key profiles, first after the chain waves and then on
    # raw bytes as a compatibility fallback.
    seen: set[tuple[int, bytes]] = set()
    for base_label, base in (("after chain XOR waves", chained), ("raw input fallback", data)):
        for profile_name, initial_key in KNOWN_KEYS:
            candidate = xor_incrementing_key(base, initial_key)
            fingerprint = (len(candidate), hashlib.sha1(candidate[:64] + candidate[-64:]).digest())
            if fingerprint in seen:
                continue
            seen.add(fingerprint)
            report(f"\n[*] Trying {profile_name} on {base_label}; prefix: {preview(candidate)}")
            found, binary = try_candidate(candidate, f"{profile_name} / {base_label}")
            if found:
                return found[0], found[1], True
            if binary and (best_binary is None or len(binary[0]) > len(best_binary[0])):
                best_binary = binary

    # Unknown one-byte incrementing-XOR key scan, similar to the diagnostic
    # path in decrypt_cetrainer.py. Small files are scanned automatically;
    # larger files use a 16 KiB prefix screen unless exhaustive scan is forced.
    scan_bases = [("raw input", data)]
    if chained != data:
        scan_bases.append(("after chain XOR waves", chained))

    use_prefix_screen = not exhaustive_scan and (deep_scan or len(data) > AUTO_SCAN_LIMIT)
    scan_jobs: list[tuple[str, bytes, int]] = []
    if exhaustive_scan:
        report("\n[*] EXHAUSTIVE scan: full-file screening of all 256 keys on both data bases.")
        for base_label, base in scan_bases:
            scan_jobs.extend((base_label, base, key) for key in range(256))
    elif use_prefix_screen:
        report(
            f"\n[*] Fast unknown-key scan: screening 256 keys on each base using up to "
            f"{SCAN_PREFIX_BYTES:,} bytes per candidate."
        )
        for base_label, base in scan_bases:
            prefix = base[:SCAN_PREFIX_BYTES]
            for key in range(256):
                candidate_prefix = xor_incrementing_key(prefix, key)
                if prefix_candidate_looks_plausible(candidate_prefix):
                    report(f"[*] Promising key 0x{key:02X} on {base_label}; verifying full file.")
                    scan_jobs.append((base_label, base, key))
            report(f"[*] Prefix screening completed for {base_label}.")
        if not scan_jobs:
            report("[!] Prefix screening found no promising key. It is not conclusive; use --exhaustive-scan.")
    else:
        report(f"\n[*] Small-file scan: full-file testing all 256 keys on each data base.")
        for base_label, base in scan_bases:
            scan_jobs.extend((base_label, base, key) for key in range(256))

    tested = 0
    scan_seen: set[tuple[int, bytes]] = set()
    for base_label, base, key in scan_jobs:
        candidate = xor_incrementing_key(base, key)
        fingerprint = (len(candidate), hashlib.sha1(candidate[:64] + candidate[-64:]).digest())
        if fingerprint in scan_seen:
            continue
        scan_seen.add(fingerprint)
        found, binary = try_candidate(candidate, f"{base_label} / scanned key 0x{key:02X}", quiet=True)
        tested += 1
        if found:
            report(f"[+] Unknown-key scan succeeded with key 0x{key:02X} on {base_label} after {tested} full-file candidate(s).")
            return found[0], found[1], True
        if binary and (best_binary is None or len(binary[0]) > len(best_binary[0])):
            best_binary = binary
        if tested % 64 == 0:
            report(f"[*] Full-file scan progress: {tested} candidate(s) checked.")

    if best_binary is not None:
        report("\n[!] No validated CheatTable XML was found.")
        report("[!] Saving the largest decompressed candidate as an unverified .decoded.bin for analysis.")
        return best_binary[0], best_binary[1] + " / UNVERIFIED", False

    raise RuntimeError(
        "No valid CheatTable XML was recovered. The file may use another protection variant, "
        "or exhaustive scan may be needed. The source file was not changed."
    )


def choose_input() -> Optional[Path]:
    """Open a file picker when launched without a path."""
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        filename = filedialog.askopenfilename(
            title="Select a Cheat Engine .CETRAINER file to decode",
            filetypes=[
                ("Cheat Engine files", "*.CETRAINER *.cetrainer *.CT *.ct"),
                ("All files", "*.*"),
            ],
        )
        root.destroy()
        if filename:
            return Path(filename)
    except Exception as exc:
        report(f"[!] File picker unavailable: {type(exc).__name__}: {exc}")

    try:
        value = input("Enter the full path to the input file (or press Enter to cancel): ").strip().strip('"')
    except (EOFError, KeyboardInterrupt):
        return None
    return Path(value).expanduser() if value else None


def unique_path(path: Path) -> Path:
    """Choose a free output path instead of overwriting an existing file."""
    if not path.exists():
        return path
    for number in range(1, 10000):
        candidate = path.with_name(f"{path.stem}_{number}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise OSError(f"Could not find a free output filename based on {path.name}")


def write_log(preferred_path: Path) -> Optional[Path]:
    """Write the diagnostic log beside input/output, falling back beside script."""
    contents = "\n".join(LOG_LINES) + "\n"
    fallback = Path(__file__).resolve().with_name("decrypt_cetrainer_barracuda.log")
    tried: set[Path] = set()
    for target in (preferred_path, fallback):
        try:
            target = target.resolve()
            if target in tried:
                continue
            tried.add(target)
            target.write_text(contents, encoding="utf-8", errors="replace")
            return target
        except OSError:
            continue
    return None


def pause_if_interactive() -> None:
    if sys.stdin and sys.stdin.isatty() and sys.platform == "win32":
        try:
            input("\nPress Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass


def main() -> int:
    parser = argparse.ArgumentParser(description="Decode Barracuda-protected Cheat Engine trainer samples.")
    parser.add_argument("input", nargs="?", help="Input file; omit to open a file picker")
    parser.add_argument("-o", "--output", help="Explicit output filename")
    parser.add_argument("--deep-scan", action="store_true", help="Force prefix-screened unknown-key scan")
    parser.add_argument(
        "--exhaustive-scan",
        action="store_true",
        help="Test all 256 keys against full files, with and without chain XOR (slow)",
    )
    args = parser.parse_args()

    if args.deep_scan and args.exhaustive_scan:
        parser.error("--deep-scan and --exhaustive-scan are mutually exclusive")

    source = Path(args.input).expanduser() if args.input else choose_input()
    if source is None:
        report("[!] No input file selected; nothing changed.")
        pause_if_interactive()
        return 2

    try:
        source = source.resolve()
    except OSError:
        source = source.absolute()

    if not source.is_file():
        report(f"[!] Input does not exist or is not a regular file: {source}")
        log_path = write_log(source.parent / f"{source.name}.decrypt.log")
        if log_path:
            report(f"[*] Diagnostic log: {log_path}")
        pause_if_interactive()
        return 2

    try:
        original = source.read_bytes()
    except OSError as exc:
        report(f"[!] Could not read input: {type(exc).__name__}: {exc}")
        write_log(source.parent / f"{source.name}.decrypt.log")
        pause_if_interactive()
        return 2

    report(f"[*] Source path: {source}")
    try:
        decoded, method, is_xml = decode(
            original,
            deep_scan=args.deep_scan,
            exhaustive_scan=args.exhaustive_scan,
        )
        if args.output:
            output = Path(args.output).expanduser().resolve()
        elif is_xml:
            output = source.with_suffix(".decoded.xml")
        else:
            output = source.with_name(source.name + ".decoded.bin")

        if output == source:
            output = source.with_name(source.stem + ".decoded" + source.suffix)
        output = unique_path(output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_bytes(decoded)

        report("\n[+] Finished.")
        report(f"    Method: {method}")
        report(f"    Output: {output}")
        report(f"    Size: {len(decoded):,} bytes")
        report(f"    SHA-256: {sha256(decoded)}")
        report(f"    Valid CheatTable XML: {is_xml}")
        if not is_xml:
            report("[!] Output is an unverified binary candidate, not a validated XML table.")

        log_path = write_log(output.parent / f"{source.name}.decrypt.log")
        if log_path:
            report(f"[*] Diagnostic log: {log_path}")
            # Also include the final log-path line in the saved log.
            try:
                log_path.write_text("\n".join(LOG_LINES) + "\n", encoding="utf-8", errors="replace")
            except OSError:
                pass
        else:
            report("[!] Could not write a diagnostic log beside the input/output or script.")
        pause_if_interactive()
        return 0 if is_xml else 1

    except Exception as exc:
        report(f"\n[!] DECODE FAILED: {type(exc).__name__}: {exc}")
        report("[!] The input file was not modified.")
        log_path = write_log(source.parent / f"{source.name}.decrypt.log")
        if log_path:
            report(f"[*] Diagnostic log: {log_path}")
        pause_if_interactive()
        return 1


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        report("\n[!] Interrupted by user.")
        write_log(Path(__file__).resolve().with_name("decrypt_cetrainer_barracuda.log"))
        pause_if_interactive()
        raise SystemExit(130)
