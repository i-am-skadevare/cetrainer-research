#!/usr/bin/env python3
"""Universal-ish offline decoder for known Cheat Engine .CETRAINER variants.

Supports the algorithms present in the supplied scripts:
- Classic Cheat Engine: chained XOR waves + incrementing key 0xCE
- Barracuda variants: incrementing key 0xCB / 0xCF
- Barracuda / modified Cheat Engine 6.7 BRICKED variant discovered in the supplied trainer (key 0xCA, step +5)
- MrAntiFun variants: known sequences of incrementing XOR rounds

Also tries plain XML, common DEFLATE wrappers, CHEAT header layouts with/without
4-byte size fields, optional 4-byte decompressed prefixes, and a default
prefix-screened scan of all 256 single-byte starting keys. The key scan checks
both the raw bytes and the bytes after the two XOR-chain waves. Full-file brute
force is available as a separate, explicitly slower mode. It never executes trainer files.

Usage:
    python decrypt_cetrainer.py                  # file picker
    python decrypt_cetrainer.py file.CETRAINER
    python decrypt_cetrainer.py file.CETRAINER -o output.xml
    python decrypt_cetrainer.py file.CETRAINER --deep-scan
    python decrypt_cetrainer.py file.CETRAINER --exhaustive-scan
"""

from __future__ import annotations

import argparse
import hashlib
import sys
import zlib
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Sequence, Tuple

PROGRAM_NAME = "decrypt_cetrainer.py"
MAX_DECOMPRESSED_BYTES = 512 * 1024 * 1024  # safety cap for malformed inputs
AUTO_SCAN_LIMIT = 128 * 1024  # auto exhaustive scan only for small files
SCAN_PREFIX_BYTES = 16 * 1024  # only this prefix is transformed for each key candidate
SCAN_PREFIX_OUTPUT_BYTES = 32 * 1024  # maximum decompressed output used to screen a key

# Each value is the starting byte of an incrementing XOR pass. MrAntiFun applies
# several such passes sequentially; the entries below are based on the supplied file.
KEY_PROFILES: Sequence[Tuple[str, Tuple[int, ...]]] = (
    ("Classic Cheat Engine (0xCE)", (0xCE,)),
    ("Barracuda (0xCB)", (0xCB,)),
    ("Barracuda (0xCF)", (0xCF,)),
    ("MrAntiFun / modified CE 6.4 32-bit", (0x2A, 0xAD, 0x2B, 0x41)),
    ("MrAntiFun / modified CE 6.5 64-bit", (0x65, 0x42, 0x17, 0x43, 0x65)),
    ("MrAntiFun / modified CE 6.5 variant", (0x65, 0x42, 0x17, 0x43)),
)
DEFLATE_MODES: Sequence[Tuple[str, int]] = (
    ("raw-deflate", -zlib.MAX_WBITS),
    ("zlib", zlib.MAX_WBITS),
    ("gzip", zlib.MAX_WBITS | 16),
)

LOG_LINES: List[str] = []


def report(message: str = "") -> None:
    print(message, flush=True)
    LOG_LINES.append(message)


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def preview(data: bytes, count: int = 24) -> str:
    return data[:count].hex(" ") or "<empty>"


def valid_cheattable_xml(data: bytes) -> bool:
    """Return True only when the bytes parse as XML with a CheatTable root."""
    if not data:
        return False
    try:
        root = ET.fromstring(data)
    except (ET.ParseError, ValueError, UnicodeError):
        return False
    tag = root.tag
    if not isinstance(tag, str):
        return False
    local_name = tag.rsplit("}", 1)[-1].split(":")[-1]
    return local_name.casefold() == "cheattable"


def looks_like_xml_text(data: bytes) -> bool:
    """A cheap diagnostic heuristic; this is not used as proof of valid XML."""
    sample = data[:512].lstrip(b"\xef\xbb\xbf \t\r\n\x00")
    return (
        sample.startswith(b"<?xml")
        or sample.startswith(b"<CheatTable")
        or b"<CheatTable" in sample
    )


def chained_xor_waves(data: bytes) -> bytes:
    """Apply the two XOR-chain waves used by the supplied decryptors."""
    result = bytearray(data)
    for i in range(2, len(result)):
        result[i] ^= result[i - 2]
    for i in range(len(result) - 2, -1, -1):
        result[i] ^= result[i + 1]
    return bytes(result)


def xor_incrementing_key(data: bytes, initial_key: int) -> bytes:
    result = bytearray(data)
    key = initial_key & 0xFF
    for i in range(len(result)):
        result[i] ^= key
        key = (key + 1) & 0xFF
    return bytes(result)


def xor_step_key(data: bytes, initial_key: int, step: int) -> bytes:
    """Apply an incrementing XOR key with a configurable byte step."""
    result = bytearray(data)
    key = initial_key & 0xFF
    step &= 0xFF
    for i in range(len(result)):
        result[i] ^= key
        key = (key + step) & 0xFF
    return bytes(result)


def apply_key_rounds(data: bytes, starting_keys: Sequence[int]) -> bytes:
    result = bytearray(data)
    for initial_key in starting_keys:
        key = initial_key & 0xFF
        for i in range(len(result)):
            result[i] ^= key
            key = (key + 1) & 0xFF
    return bytes(result)


def infer_single_key_from_cheat_header(data: bytes) -> Optional[int]:
    """Infer a single incrementing XOR key if it reveals the known CHEAT marker."""
    magic = b"CHEAT"
    if len(data) < len(magic):
        return None
    guessed = data[0] ^ magic[0]  # at offset zero, keystream byte equals initial key
    candidate = xor_incrementing_key(data[: len(magic)], guessed)
    return guessed if candidate == magic else None


def contains_cheattable_marker(data: bytes) -> bool:
    """Check a short decoded/decompressed prefix for a likely XML signature."""
    sample = data[:SCAN_PREFIX_OUTPUT_BYTES]
    stripped = sample.lstrip(b"\xef\xbb\xbf \t\r\n\x00")
    return (
        stripped.startswith(b"<?xml")
        or stripped.lower().startswith(b"<cheattable")
        or b"<cheattable" in sample.lower()
    )


def prefix_candidate_looks_plausible(candidate_prefix: bytes) -> bool:
    """Screen one key with a prefix; the complete file is verified separately."""
    if not candidate_prefix:
        return False
    if contains_cheattable_marker(candidate_prefix) or candidate_prefix.startswith(b"CHEAT"):
        return True

    if candidate_prefix.startswith(b"CHEAT"):
        payloads = [candidate_prefix[5:]]
        if len(candidate_prefix) > 9:
            payloads.append(candidate_prefix[9:])
    else:
        payloads = [candidate_prefix]
        if len(candidate_prefix) > 4:
            payloads.append(candidate_prefix[4:])

    for payload in payloads:
        if not payload:
            continue
        for _, wbits in DEFLATE_MODES:
            try:
                stream = zlib.decompressobj(wbits)
                inflated = stream.decompress(payload, SCAN_PREFIX_OUTPUT_BYTES)
            except (zlib.error, ValueError):
                continue
            if contains_cheattable_marker(inflated):
                return True
    return False


def screen_incrementing_keys(data: bytes, base_label: str) -> List[int]:
    """Screen all 256 one-byte starting keys against only a short prefix.

    The full input may have been preprocessed once before this function (for
    example, by the chained XOR waves), but each candidate key here transforms
    at most SCAN_PREFIX_BYTES. Full-file work happens only after a candidate
    passes the prefix screen.
    """
    prefix = data[:SCAN_PREFIX_BYTES]
    candidates: List[int] = []
    report(
        f"[*] Fast key screening ({base_label}): 256 one-byte starting keys; "
        f"only {len(prefix):,} bytes are transformed per key candidate."
    )
    for key in range(256):
        decoded_prefix = xor_incrementing_key(prefix, key)
        if prefix_candidate_looks_plausible(decoded_prefix):
            candidates.append(key)
            report(
                f"[*] {base_label}: key 0x{key:02X} has a plausible "
                "XML/DEFLATE prefix; verifying full file."
            )
        if (key + 1) % 64 == 0:
            report(f"[*] {base_label} prefix-screen progress: {key + 1} / 256 keys checked.")
    return candidates


def bounded_decompress(data: bytes, wbits: int) -> bytes:
    """Decompress a stream with an output cap to avoid runaway expansion."""
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


def payload_variants(data: bytes) -> List[Tuple[str, bytes]]:
    """Return plausible compressed-payload locations without assuming one header layout."""
    variants: List[Tuple[str, bytes]] = []
    seen = set()

    def add(label: str, payload: bytes) -> None:
        if not payload:
            return
        # Avoid repeating identical bytes under multiple labels.
        marker = (len(payload), hashlib.sha1(payload[:64] + payload[-64:]).digest())
        if marker not in seen:
            seen.add(marker)
            variants.append((label, payload))

    if data.startswith(b"CHEAT"):
        add("CHEAT payload (offset 5)", data[5:])
        if len(data) >= 9:
            size_bytes = data[5:9]
            add("CHEAT payload after 4-byte size (offset 9)", data[9:])
            # Some variants store the compressed payload size after CHEAT.
            for endian in ("little", "big"):
                declared = int.from_bytes(size_bytes, endian, signed=False)
                remaining = len(data) - 9
                if 0 < declared <= remaining:
                    add(
                        f"CHEAT payload using {endian}-endian size ({declared} bytes)",
                        data[9 : 9 + declared],
                    )
    else:
        add("whole candidate", data)
        # A few wrappers place a 32-bit length before the compressed stream.
        if len(data) >= 5:
            declared_le = int.from_bytes(data[:4], "little", signed=False)
            declared_be = int.from_bytes(data[:4], "big", signed=False)
            remaining = len(data) - 4
            add("candidate after possible 4-byte prefix", data[4:])
            for endian, declared in (("little", declared_le), ("big", declared_be)):
                if 0 < declared <= remaining:
                    add(
                        f"payload using {endian}-endian size ({declared} bytes)",
                        data[4 : 4 + declared],
                    )
    return variants


def output_variants(data: bytes) -> List[Tuple[str, bytes]]:
    """Try both the complete inflate result and the known 4-byte-prefix variant."""
    variants: List[Tuple[str, bytes]] = [("full output", data)]
    if len(data) >= 4:
        stripped = data[4:]
        # Prefer describing this as a size field only when it agrees with output length.
        declared_le = int.from_bytes(data[:4], "little", signed=False)
        declared_be = int.from_bytes(data[:4], "big", signed=False)
        if declared_le == len(stripped) or declared_be == len(stripped):
            variants.insert(0, ("output after matching 4-byte length prefix", stripped))
        else:
            variants.append(("output after 4-byte prefix (legacy CHEAT variant)", stripped))
    return variants


def nonxml_score(data: bytes) -> float:
    """Rank non-XML inflate results so the most plausible one can be saved for diagnosis."""
    if not data:
        return -1.0
    sample = data[:8192]
    printable = sum(byte in (9, 10, 13) or 32 <= byte < 127 for byte in sample)
    ratio = printable / max(1, len(sample))
    score = ratio * 40.0 + min(len(data).bit_length(), 32) * 0.1
    if looks_like_xml_text(data):
        score += 50.0
    if b"<CheatTable" in sample:
        score += 25.0
    return score


@dataclass
class BestBinary:
    data: bytes
    method: str
    score: float


def inspect_candidate(
    candidate: bytes,
    label: str,
    best_binary: Optional[BestBinary],
    quiet: bool = False,
) -> Tuple[Optional[Tuple[bytes, str]], Optional[BestBinary]]:
    """Try a candidate as XML and as a compressed payload; return XML or update best binary."""
    if valid_cheattable_xml(candidate):
        report(f"[+] Valid CheatTable XML found directly: {label}")
        return (candidate, label), best_binary

    for payload_label, payload in payload_variants(candidate):
        for mode, wbits in DEFLATE_MODES:
            try:
                inflated = bounded_decompress(payload, wbits)
            except (zlib.error, ValueError) as exc:
                if not quiet:
                    report(f"[-] {label} / {payload_label} / {mode}: {exc}")
                continue

            description = f"{label} / {payload_label} / {mode}"
            if not quiet:
                report(f"[+] Inflate succeeded: {description} ({len(inflated):,} bytes)")
                report(f"    Inflated prefix: {preview(inflated)}")

            for out_label, output in output_variants(inflated):
                method = f"{description} / {out_label}"
                if valid_cheattable_xml(output):
                    report(f"[+] Valid CheatTable XML found: {method}")
                    return (output, method), best_binary

                score = nonxml_score(output)
                if best_binary is None or score > best_binary.score:
                    best_binary = BestBinary(output, method, score)

    return None, best_binary


def decode(data: bytes, deep_scan: bool = False, exhaustive_scan: bool = False) -> Tuple[bytes, str, bool]:
    """Try supported CETRAINER variants and return (bytes, method, is_xml)."""
    if not data:
        raise ValueError("The selected file is empty.")

    report(f"[*] Input size: {len(data):,} bytes")
    report(f"[*] Input SHA-256: {sha256(data)}")
    report(f"[*] Input prefix: {preview(data)}")

    best_binary: Optional[BestBinary] = None

    # 1. Plain .CT/.CETRAINER XML, or data already carrying a directly decodable stream.
    found, best_binary = inspect_candidate(data, "original bytes", best_binary)
    if found:
        return found[0], found[1], True

    # 2. Test compression after only the first two XOR-chain waves.
    chained = chained_xor_waves(data)
    report(f"[*] After the two chained XOR waves: {preview(chained)}")
    found, best_binary = inspect_candidate(chained, "chain waves only", best_binary)
    if found:
        return found[0], found[1], True

    # 2b. Barracuda / modified CE 6.7 variant found in the supplied trainer.
    # The two chained waves are followed by an XOR key starting at 0xCA and
    # incrementing by 5. The decoded wrapper is BRICKED 00 15 00 + raw DEFLATE;
    # the inflated stream begins with a 4-byte little-endian XML length. Validate
    # every marker/length/XML condition before accepting this specialized path.
    bricked = xor_step_key(chained, 0xCA, 5)
    if bricked.startswith(b"BRICKED\x00\x15\x00"):
        report("\n[+] Matched modified Barracuda/CE 6.7 wrapper: BRICKED + 00 15 00; key 0xCA, step +5.")
        try:
            inflated = bounded_decompress(bricked[10:], -zlib.MAX_WBITS)
            report(f"[*] BRICKED raw-DEFLATE output: {len(inflated):,} bytes; prefix {preview(inflated)}")
            if len(inflated) >= 4:
                declared_size = int.from_bytes(inflated[:4], "little", signed=False)
                xml_payload = inflated[4:]
                if declared_size == len(xml_payload) and valid_cheattable_xml(xml_payload):
                    report(f"[+] BRICKED variant validated: XML length prefix matches ({declared_size:,} bytes).")
                    return xml_payload, "Barracuda / modified CE 6.7 (BRICKED, key 0xCA step +5)", True
                report(
                    f"[-] BRICKED payload did not validate: declared XML size {declared_size:,}, "
                    f"actual {len(xml_payload):,}; valid CheatTable XML={valid_cheattable_xml(xml_payload)}."
                )
            else:
                report("[-] BRICKED DEFLATE output is too short to contain a length prefix.")
        except (zlib.error, ValueError) as exc:
            report(f"[-] BRICKED variant matched its header but failed decompression/validation: {exc}")

    # 3. Known CE / Barracuda / MrAntiFun key profiles, using the documented chain order.
    seen_candidates = set()
    for profile_name, starts in KEY_PROFILES:
        candidate = apply_key_rounds(chained, starts)
        fingerprint = hashlib.sha1(candidate[:64] + candidate[-64:]).digest()
        if fingerprint in seen_candidates:
            continue
        seen_candidates.add(fingerprint)
        report(f"\n[*] Trying profile: {profile_name}; prefix: {preview(candidate)}")
        found, best_binary = inspect_candidate(candidate, profile_name, best_binary)
        if found:
            return found[0], found[1], True

    # 4. If the transformed data reveals CHEAT after a single incrementing wave,
    # infer an unlisted initial key rather than limiting ourselves to known constants.
    inferred_key = infer_single_key_from_cheat_header(chained)
    if inferred_key is not None and inferred_key not in (0xCE, 0xCB, 0xCF):
        label = f"inferred incrementing key 0x{inferred_key:02X}"
        candidate = xor_incrementing_key(chained, inferred_key)
        report(f"\n[+] CHEAT signature suggests {label}; trying it.")
        found, best_binary = inspect_candidate(candidate, label, best_binary)
        if found:
            return found[0], found[1], True
    elif inferred_key is not None:
        report(f"[*] CHEAT signature implies a known single-wave key: 0x{inferred_key:02X}.")

    # 5. Also test key profiles without the chain waves as a compatibility fallback.
    # Not part of the standard algorithms, but harmless to try and occasionally useful.
    report("\n[*] Trying known key profiles without the chain waves as a fallback.")
    for profile_name, starts in KEY_PROFILES:
        candidate = apply_key_rounds(data, starts)
        found, best_binary = inspect_candidate(candidate, profile_name + " / no chain", best_binary, quiet=True)
        if found:
            report(f"[+] Fallback profile succeeded: {found[1]}")
            return found[0], found[1], True

    # 6. Unknown single-byte incrementing-key variants.
    # Scan both plausible preprocessing orders:
    #   - raw input (no chain waves)
    #   - input after the two chain waves
    # For large files this prefix-screened scan is now automatic; --deep-scan
    # explicitly requests the same fast scan on small files too. Only candidates
    # that look like CHEAT/XML or inflate to an XML prefix are applied to the
    # entire file. --exhaustive-scan skips screening and checks all 256 keys on
    # both bases.
    scan_bases: List[Tuple[str, bytes]] = [("raw input / no chain waves", data)]
    if chained != data:
        scan_bases.append(("after two XOR-chain waves", chained))

    scan_candidates: List[Tuple[str, bytes, int]] = []
    use_prefix_screen = (not exhaustive_scan) and (deep_scan or len(data) > AUTO_SCAN_LIMIT)

    if exhaustive_scan:
        report(
            "\n[*] EXHAUSTIVE scan: checking every one-byte starting key against "
            "the full file for both raw and chain-wave bases (up to 512 candidates)."
        )
        for base_label, base_data in scan_bases:
            scan_candidates.extend((base_label, base_data, key) for key in range(256))
    elif use_prefix_screen:
        report(
            "\n[*] Fast key scan is enabled by default for this file. "
            "Screening 256 one-byte starting keys on each applicable preprocessing base."
        )
        for base_label, base_data in scan_bases:
            keys = screen_incrementing_keys(base_data, base_label)
            scan_candidates.extend((base_label, base_data, key) for key in keys)
        if not scan_candidates:
            report(
                "[!] Prefix screening found no promising key candidate on either base. "
                "The scan is not conclusive for protections that do not expose a "
                "CHEAT/XML signature or XML after DEFLATE near the beginning. "
                "Use --exhaustive-scan to test all 256 keys against the full file."
            )
    else:
        # Small files retain the thorough automatic scan, but test both bases.
        report(
            f"\n[*] Small-file fallback: checking all 256 one-byte starting keys "
            f"against the full {len(data):,}-byte input on each applicable base."
        )
        for base_label, base_data in scan_bases:
            scan_candidates.extend((base_label, base_data, key) for key in range(256))

    tested = 0
    seen_full_candidates = set()
    for base_label, base_data, key in scan_candidates:
        candidate = xor_incrementing_key(base_data, key)
        fingerprint = (len(candidate), hashlib.sha1(candidate[:64] + candidate[-64:]).digest())
        if fingerprint in seen_full_candidates:
            continue
        seen_full_candidates.add(fingerprint)
        found, best_binary = inspect_candidate(
            candidate,
            f"{base_label} / single incrementing key 0x{key:02X}",
            best_binary,
            quiet=True,
        )
        tested += 1
        if found:
            report(
                f"[+] Single-key scan succeeded on {base_label} with key 0x{key:02X} "
                f"after {tested} full-file candidate(s)."
            )
            return found[0], found[1], True
        if tested % 64 == 0:
            report(f"[*] Full-file candidate verification: {tested} checked.")

    if scan_candidates:
        report(f"[*] Key scan finished: {tested} full-file candidate(s); no valid CheatTable XML.")

    if best_binary is not None:
        report("[!] Decompression produced data, but none parsed as a valid CheatTable XML document.")
        report(f"[!] Best diagnostic candidate: {best_binary.method}")
        return best_binary.data, best_binary.method + " [unverified binary]", False

    raise RuntimeError(
        "No supported variant produced a valid CheatTable XML document or a usable decompressed result. "
        "The file may use an undocumented protection method, be a standalone trainer EXE, or not be a CETRAINER."
    )


def choose_input() -> Optional[Path]:
    try:
        import tkinter as tk
        from tkinter import filedialog

        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        chosen = filedialog.askopenfilename(
            title="Select a Cheat Engine trainer/table file",
            filetypes=[
                ("Cheat Engine files", "*.CETRAINER *.cetrainer *.CT *.ct *.xml *.XML"),
                ("All files", "*.*"),
            ],
        )
        root.destroy()
        if chosen:
            return Path(chosen)
    except Exception as exc:
        report(f"[!] File picker unavailable: {type(exc).__name__}: {exc}")

    try:
        raw = input("Enter the full path to the .CETRAINER/.CT file (Enter to cancel): ").strip()
    except (EOFError, KeyboardInterrupt):
        return None
    raw = raw.strip('"')
    return Path(raw).expanduser() if raw else None


def ask_deep_scan_gui(source: Path) -> bool:
    """Let double-click users opt into prefix-screened scanning for large files."""
    try:
        import tkinter as tk
        from tkinter import messagebox

        root = tk.Tk()
        root.withdraw()
        try:
            root.attributes("-topmost", True)
        except Exception:
            pass
        size = source.stat().st_size
        answer = messagebox.askyesno(
            "Unknown-key scan",
            f"The selected file is {size:,} bytes and exceeds the automatic scan limit.\n\n"
            "Run the fast deep scan? It tests all 256 one-byte starting keys using only a "
            "short prefix, then verifies the full file only for promising candidates.\n\n"
            "If no candidate is found, --exhaustive-scan runs the slower full-file scan.",
            parent=root,
        )
        root.destroy()
        return bool(answer)
    except Exception:
        return False


def unique_path(path: Path) -> Path:
    if not path.exists():
        return path
    for number in range(1, 10000):
        candidate = path.with_name(f"{path.stem}_{number}{path.suffix}")
        if not candidate.exists():
            return candidate
    raise OSError(f"Could not find an unused output filename based on {path.name}")


def write_log(source: Optional[Path]) -> Optional[Path]:
    text = "\n".join(LOG_LINES) + "\n"
    targets: List[Path] = []
    if source is not None:
        targets.append(source.with_name(source.name + ".decrypt.log"))
    targets.append(Path(__file__).resolve().with_name("decrypt_cetrainer.log"))
    for target in targets:
        try:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(text, encoding="utf-8", errors="replace")
            return target
        except OSError:
            continue
    return None


def pause_if_double_clicked() -> None:
    if sys.platform == "win32" and sys.stdin and sys.stdin.isatty():
        try:
            input("\nPress Enter to close this window...")
        except (EOFError, KeyboardInterrupt):
            pass


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Decode known protected Cheat Engine .CETRAINER variants to XML."
    )
    parser.add_argument("input", nargs="?", help="Input file; if omitted, a file picker opens")
    parser.add_argument("-o", "--output", help="Output file path")
    parser.add_argument(
        "--deep-scan",
        action="store_true",
        help="Force fast prefix-screened scan on small files too (large files are scanned by default)",
    )
    parser.add_argument(
        "--exhaustive-scan",
        action="store_true",
        help="Slow exhaustive fallback: test all 256 keys against the full file, both with and without chain waves",
    )
    args = parser.parse_args()

    source = Path(args.input).expanduser() if args.input else choose_input()
    if source is None:
        report("[!] No input file selected. Nothing was changed.")
        log = write_log(None)
        if log:
            report(f"[*] Diagnostic log: {log.resolve()}")
            write_log(None)
        pause_if_double_clicked()
        return 2

    try:
        source = source.resolve()
    except OSError:
        source = source.absolute()

    report(f"[*] Source: {source}")
    if not source.is_file():
        report(f"[!] Input file does not exist or is not a regular file: {source}")
        log = write_log(source)
        if log:
            report(f"[*] Diagnostic log: {log.resolve()}")
            write_log(source)
        pause_if_double_clicked()
        return 2

    # Large files automatically receive the fast prefix-screened scan inside decode().
    # --deep-scan also enables that scan for small files; --exhaustive-scan opts into
    # the slower full-file verification of every one-byte starting key.
    deep_scan = args.deep_scan

    try:
        original = source.read_bytes()
    except OSError as exc:
        report(f"[!] Cannot read input file: {type(exc).__name__}: {exc}")
        log = write_log(source)
        if log:
            report(f"[*] Diagnostic log: {log.resolve()}")
            write_log(source)
        pause_if_double_clicked()
        return 2

    try:
        decoded, method, is_xml = decode(
            original,
            deep_scan=deep_scan,
            exhaustive_scan=args.exhaustive_scan,
        )
        if args.output:
            target = Path(args.output).expanduser().resolve()
        elif is_xml:
            target = source.with_suffix(".xml")
        else:
            target = source.with_name(source.name + ".decoded.bin")

        # Never replace the source or a previous result without warning.
        if target == source:
            target = source.with_name(source.stem + ".decrypted" + source.suffix)
        target = unique_path(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(decoded)

        report("\n[+] Finished.")
        report(f"    Method: {method}")
        report(f"    Output: {target.resolve()}")
        report(f"    Bytes written: {len(decoded):,}")
        report(f"    SHA-256: {sha256(decoded)}")
        report(f"    Valid CheatTable XML: {is_xml}")
        if not is_xml:
            report("[!] The output is unverified binary data; it was not given an .xml extension.")

    except Exception as exc:
        report(f"\n[!] DECODE FAILED: {type(exc).__name__}: {exc}")
        report("[!] The original file was not modified.")
        log = write_log(source)
        if log:
            report(f"[*] Diagnostic log: {log.resolve()}")
            write_log(source)
        pause_if_double_clicked()
        return 1

    log = write_log(source)
    if log:
        report(f"[*] Diagnostic log: {log.resolve()}")
        write_log(source)
    else:
        report("[!] Could not write the diagnostic log beside the input or script.")
    pause_if_double_clicked()
    return 0 if is_xml else 3


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except KeyboardInterrupt:
        report("\n[!] Cancelled by user.")
        write_log(None)
        pause_if_double_clicked()
        raise SystemExit(130)
