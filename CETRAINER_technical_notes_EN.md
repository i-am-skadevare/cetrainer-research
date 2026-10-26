# CETRAINER Research: Barracuda and MrAntiFun

**Research author:** Pauline Solheim (`skadevare`)  
**GitHub:** [@i-am-skadevare](https://github.com/i-am-skadevare)

**Type of work:** Research into CETRAINER formats, analysis of existing Python scripts, extraction of data from standalone trainer archives, diagnostics of XOR transformations, and validation of recovered XML tables.

> This report covers two specific trainer samples: Watch Dogs by Barracuda and Splinter Cell: Blacklist by MrAntiFun. It does not claim support for all trainers by these authors, nor does it present AlexAltea's original algorithms as my own work.

## 1. Research Objective

I examined the internal structure of two protected Cheat Engine files to understand why standard recovery methods do not work for every variant of the format.

The starting point was the [AlexAltea/cetrainer-unpacker](https://github.com/AlexAltea/cetrainer-unpacker) project, which includes separate implementations for Barracuda and MrAntiFun.

The goal was not to develop a universal decoder, but to investigate specific files: analyze the source code, test the suspected transformations, diagnose errors, and obtain results whose correctness could be checked using XML structure, file size, and SHA-256.

Two independent cases were investigated:

- **Watch Dogs / Barracuda / Cheat Engine 6.7**
- **Splinter Cell: Blacklist / MrAntiFun / Cheat Engine 6.4, 32-bit**

## 2. Original Projects and Algorithms

Primary sources:

- [Original Barracuda script](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/unpackers/unpack_cet_barracuda.py)
- [Original MrAntiFun script](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/unpackers/unpack_cet_mrantifun.py)
- [General CETRAINER documentation](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/docs/cetrainer.md)
- [Barracuda variant documentation](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/docs/cetrainer-barracuda.md)
- [MrAntiFun variant documentation](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/docs/cetrainer-mrantifun.md)

In general, a protected `.CETRAINER` contains a compressed Cheat Engine XML table that has been processed using several XOR transformations. A standalone trainer `.EXE` may add another packaging layer: the archive contains the `.CETRAINER` itself, the Cheat Engine engine executable, and the required DLLs.

Therefore, in both investigations, it was important to distinguish **extracting a file from a container** from **decoding the file itself**.

### Common Transformation Steps

Both original implementations use two chained XOR passes.

The first pass processes the data from beginning to end:

```python
for i in range(2, len(data)):
    data[i] ^= data[i - 2]
```

The second pass processes it in reverse:

```python
for i in range(len(data) - 2, -1, -1):
    data[i] ^= data[i + 1]
```

Additional XOR passes are applied afterward. This is where the variants examined here begin to differ.

The original Barracuda script tests keys `0xCB` and `0xCF`. The MrAntiFun script tests several sequences of initial keys, including `2A AD 2B 41`, which the author identifies as a modified Cheat Engine 6.4, 32-bit variant.

### Diagnostic Code Improvements

During the investigation, I prepared modified Python versions focused on observability and result validation.

The following diagnostics were added or expanded:

- reporting the input file size and SHA-256;
- displaying the first bytes in hexadecimal;
- diagnosing the results of the chained XOR transformations;
- reporting the profile being tested and decompression errors;
- trying raw DEFLATE, zlib, and gzip decompression;
- handling a four-byte field preceding the XML cautiously;
- saving the output file path, size, and hash;
- separating decompressed but unverified data from output identified as XML.

For the large Barracuda file, I also added a preliminary search using a short prefix: for each single-byte key, only part of the file is transformed, while a full check is performed for candidates that pass the preliminary filter. A slower exhaustive mode was also provided.

This search did not ultimately solve the Watch Dogs case, but it was useful for diagnostics and ruling out known variants.

---

## 3. Case Study A — Watch Dogs / Barracuda

### 3.1. Input File

The file under investigation was `CET_TRAINER.CETRAINER`.

| Property | Value |
|---|---|
| Protected file size | 214,896 bytes |
| SHA-256 | `8b4c801a0ed057f99e2066092a4a1ea21e6b667a0cfb1600d09a6ce159219618` |
| Cheat Engine version | 6.7, confirmed in the recovered LuaScript |
| Target process | `watch_dogs.exe` |

The file was present inside the standalone trainer's `CET_Archive.dat`. After extraction, its size and SHA-256 matched those of a separate `CET_TRAINER.CETRAINER` copy used in earlier diagnostic attempts.

### 3.2. Why the Original Script Did Not Work

The original `unpack_cet_barracuda.py` performs two chained XOR passes and then tries the incrementing-XOR keys `0xCB` and `0xCF`.

In this case, neither of those profiles nor the standard Cheat Engine profile with initial key `0xCE` produced a valid result.

Early logs recorded raw-DEFLATE errors, including:

- `invalid block type`;
- `invalid distance too far back`;
- `invalid code lengths set`.

This indicated that the resulting byte sequences did not match the expected compressed stream.

We also expanded the diagnostic attempts: testing multiple decompression methods, headers, and possible offsets while recording byte prefixes and candidate hashes.

The initial key-search mode had a limitation for files larger than 131,072 bytes. The search was later reworked: instead of processing the entire file at every step, it first checks a prefix of up to 16 KiB. This reduced unnecessary work, but did not automatically discover the required variant.

### 3.3. Discovered Variant

The solution emerged after adding a special branch for this specific format.

The following sequence was confirmed for the file under investigation.

**Stage 1 — Two chained XOR passes.**

Apply the two passes described above.

**Stage 2 — XOR with a step of 5.**

The initial key is `0xCA`. After each byte is processed, the key is updated as follows:

```python
key = (key + 5) & 0xFF
```

This pass differs from the original Barracuda profiles, in which the key increases by one.

**Stage 3 — Container identification.**

After the transformation, the buffer begins with this signature:

```text
BRICKED 00 15 00
```

In hexadecimal, this is `42 52 49 43 4B 45 44 00 15 00`, i.e. the ten-byte header `BRICKED\x00\x15\x00`.

**Stage 4 — Raw DEFLATE.**

The compressed stream begins at offset 10, immediately after this signature. Attempts to decompress the data without accounting for the header did not produce a valid result.

**Stage 5 — Length field and XML.**

Decompression produces 357,452 bytes. The first four bytes are a little-endian XML length field containing `357448`; the following 357,448 bytes form the XML table.

Before accepting the result, the script checks that the declared length matches the actual length and parses the XML, expecting `CheatTable` as the root element.

### 3.4. Result Validation

The recovered XML has the following properties:

| Check | Result |
|---|---|
| XML size | 357,448 bytes |
| SHA-256 | `3fc8017e7a417ec38e675dcb357839f10b7bfe8f63fff371953a0fd2f7a8bb08` |
| Root element | `CheatTable` |
| Table format version attribute | `CheatEngineTableVersion="26"` |
| Required engine version | `RequiredCEVersion=6,7` |
| Target process | `watch_dogs.exe` |

`CheatEngineTableVersion="26"` identifies the table format version, not the installed Cheat Engine engine version. The requirement for version 6.7 is confirmed separately by the LuaScript content.

### 3.5. Barracuda Case Summary

For the investigated Watch Dogs sample, the original keys `0xCB` and `0xCF` were insufficient. We identified and implemented a separate branch using the initial key `0xCA`, a `+5` increment, the `BRICKED` signature, and a raw-DEFLATE stream starting at offset 10.

The result was validated by checking the length, successfully parsing the XML, and confirming the expected target process and engine-version information.

I do not claim that this variant is used by all Barracuda trainers. This conclusion applies to the specific file examined.

---

## 4. Case Study B — Splinter Cell: Blacklist / MrAntiFun

### 4.1. Input Materials and Engine Version

At the beginning of the investigation, the source container was the `CET_Archive.dat` archive (4,426,978 bytes). The following components were extracted from or identified during archive analysis:

- `defines.lua`;
- `lua5.1-32.dll`;
- `dbghelp.dll`;
- an embedded Cheat Engine executable, 7,702,528 bytes;
- an outer trainer executable, 200,888 bytes.

Important chronology note: `decrypt_cetrainer_mrantifun.py` **was not part of the initial input materials**. We first consulted AlexAltea's original `unpack_cet_mrantifun.py`, reviewed its implementation, and identified problems that were subsequently fixed in our own diagnostic version. Sections 4.3–4.4 describe this sequence.

**Clarification about the decoded file's name:** `CET_TRAINER.CETRAINER.decoded.CT` (868,923 bytes) is not a separate entry in the original archive and is not an independent validation file. It contains the same decoded XML content saved as `CET_TRAINER.CETRAINER.decoded.xml`; `.CT` is simply an alternate filename/extension for the same content. Therefore, the `.CT` file must not be treated as an independent reference or separate evidence that decoding was correct.

The embedded engine contained the string `Cheat Engine 6.4`. Its PE header confirms Intel i386 (PE32) architecture, and `lua5.1-32.dll` is consistent with a 32-bit build.

Thus, the variant under investigation is associated with Cheat Engine 6.4, 32-bit.

### 4.2. Extracting the Protected CETRAINER

There was no separate protected `.CETRAINER` at the top level of the archive, but the file was present inside `CET_Archive.dat`.

For this container, the data was decompressed using raw DEFLATE after a four-byte prefix. The decompressed archive stream contains a directory of 21 entries. The first entry is named `CET_TRAINER.CETRAINER` and has a recorded size of 690,417 bytes.

The extracted file has the following properties:

| Property | Value |
|---|---|
| Size | 690,417 bytes |
| SHA-256 | `7328d2bde49d6d1c10269483c6bcbbf5ed6ec91002afd9ada26b9a11a2f28749` |
| Initial bytes | `0d 0b 13 1c 68 ac be 11 7f e2 0d 40 ...` |

This made it possible to move from the outer trainer executable to the content directly processed by the decoder.

### 4.3. Reviewing AlexAltea's Original Script

The original `unpack_cet_mrantifun.py` contains three sequences of initial keys:

| Profile | Initial keys |
|---|---|
| Modified CE 6.4, 32-bit | `2A AD 2B 41` |
| Modified CE 6.5, 64-bit | `65 42 17 43 65` |
| Modified CE 6.5, variant | `65 42 17 43` |

Each value defines a separate XOR pass over the entire buffer. During each pass, the key increases by one after every byte. All these passes occur after the two chained XOR passes.

If the result begins with `CHEAT`, the script skips the five-byte header and decompresses the remaining data using raw DEFLATE. After decompression, the first four bytes are removed as the length field.

**The `2A AD 2B 41` sequence was already present in the original project.** We did not rediscover that profile; it was documented by AlexAltea and was suitable for testing against the extracted file.

Reviewing the original code revealed several problems:

- The unprotected-XML check is written as `if str(data[:5]) == "<?xml":`. For `bytes`/`bytearray` in Python 3, this compares the object's string representation with the text marker, so it does not work as intended. The code should compare the bytes themselves, for example with `b"<?xml"`.
- The `except Exception as e: pass` block silently discards errors from all decompression attempts. This makes it difficult to tell which profile or processing stage failed.
- In the `CHEAT` branch, the first four decompressed bytes are removed without checking that they are a length field and that the remaining data is actually XML.

After reviewing AlexAltea's `unpack_cet_mrantifun.py`, we therefore created our own `decrypt_cetrainer_mrantifun.py` and added fixes and diagnostic checks. Our file is an output of the next stage of the work, not an initial case input.

### 4.4. Fixes in Our Version

Our `decrypt_cetrainer_mrantifun.py` retains the original key profiles and pass order, while fixing the issues listed above and making the output easier to validate.

The following were added:

- checking XML against the actual bytes instead of comparing `str(data[:5])` with a string;
- reporting the input file size, SHA-256, and initial prefix;
- displaying the result after the two chained XOR passes and the prefix after each key profile;
- reporting decompression errors instead of silently discarding them;
- trying raw DEFLATE, zlib, and gzip;
- reporting the decompressed candidate's length and SHA-256;
- removing the four-byte field only when the result after removal appears XML-like;
- preserving the original buffer without modifying the source file;
- choosing the output file extension based on the observed result and reporting final details.

One limitation of this diagnostic version is that `looks_like_xml()` checks the initial bytes but does not fully validate the XML structure. The resulting XML was therefore parsed separately.

### 4.5. Running the Fixed Version and Validation

After extracting the protected `.CETRAINER` and fixing the identified problems, I ran our own `decrypt_cetrainer_mrantifun.py` against that file.

The `2A:AD:2B:41` profile was tested first and proved to be suitable.

The observed sequence was:

1. After the two chained XOR passes, the buffer began with `AE A3 A8 B6 A1 D7 6C A4 ...`.
2. After four incrementing-XOR passes, the `CHEAT` header appeared.
3. The raw-DEFLATE stream after the five-byte header decompressed successfully to 868,927 bytes.
4. The first four bytes of the decompressed result were `3B 42 0D 00`, which is the little-endian value `868923`.
5. Removing those four bytes produced an XML file of 868,923 bytes.

The file named `CET_TRAINER.CETRAINER.decoded.CT` in the working materials is not a separate file from the archive and does not represent an independent control copy. It has the same decoded table content as the output saved by the script as `CET_TRAINER.CETRAINER.decoded.xml`, with only the extension changed to `.CT`. Comparing these two filenames therefore does not constitute an independent validation of the result.

| Check | Result |
|---|---|
| Original protected CETRAINER size | 690,417 bytes |
| Decompressed stream size, including length field | 868,927 bytes |
| Final XML size | 868,923 bytes |
| Final XML SHA-256 | `1199d1f301d20b7abe42640b6cbc7b31a0141d048878fa9eeac655dd3634a136` |
| Root element | `CheatTable` |
| `CheatEngineTableVersion` | `18` |
| Number of forms | 3 (`UDF1`, `UDF2`, `UDF3`) |
| Number of `CheatEntry` elements | 7 |

The SHA-256 shown above records the checksum of the decoded XML output. Because `CET_TRAINER.CETRAINER.decoded.CT` is the same decoded XML content under a different extension, its hash is not independent evidence that decoding was correct. Validation in this case rests on successful raw-DEFLATE decompression, agreement between the length field and the actual output size, successful XML parsing, and the expected table structure.

A naming discrepancy was also found: the outer trainer file is labeled `+6`, while the table's internal name contains `+7`. The reason for this discrepancy has not been established.

### 4.6. MrAntiFun Case Summary

In this case, we did not discover an unknown key sequence: the `2A AD 2B 41` profile was already documented in AlexAltea's original script. Our contribution was to improve diagnostics, handle the buffer more cautiously, and test different decompression modes. The result was checked against the length field, successful XML parsing, and the expected table structure; the SHA-256 records the output file's checksum but is not compared here against an independent reference.

Unlike the Barracuda case, here we were able to extract the original protected file from the archive container and decode it into a valid XML table. `CET_TRAINER.CETRAINER.decoded.CT` is not a separate archive entry or an independent reference: it is the same decoded content saved with the `.xml` extension.

---

## 5. Comparison of the Two Investigations

| Property | Watch Dogs / Barracuda | Splinter Cell: Blacklist / MrAntiFun |
|---|---|---|
| Engine version | 6.7 requirement in LuaScript | Embedded Cheat Engine 6.4, PE32 |
| Protected CETRAINER | 214,896 bytes | 690,417 bytes |
| Original profile | `0xCB` and `0xCF` failed | `2A AD 2B 41` succeeded |
| Chained XOR passes | Two | Two |
| Additional XOR transformation | One pass, key `0xCA`, step `+5` | Four passes: `2A`, `AD`, `2B`, `41`; step `+1` within each pass |
| Container signature | `BRICKED\x00\x15\x00` | `CHEAT` |
| Start of raw DEFLATE | Offset 10 | After the five-byte header |
| Length field after decompression | First four bytes | First four bytes |
| XML size | 357,448 bytes | 868,923 bytes |
| XML SHA-256 | `3fc8017e7a417ec38e675dcb357839f10b7bfe8f63fff371953a0fd2f7a8bb08` | `1199d1f301d20b7abe42640b6cbc7b31a0141d048878fa9eeac655dd3634a136` |
| Main finding | A separate variant not covered by the tested profiles | Successful use of an existing profile and structural XML validation |

Both cases show that the same `.CETRAINER` extension does not guarantee the same protection scheme. The first two XOR passes have the same structure, but the additional passes, keys, and headers differ.

## 6. My Contribution and the Role of AI

I do not claim authorship of AlexAltea's original algorithms. My work included:

1. Collecting and examining the source files and logs.
2. Analyzing existing scripts and their key profiles.
3. Testing standard variants against real files.
4. Improving diagnostic output and result validation.
5. Investigating why the standard Barracuda keys failed.
6. Implementing a separate branch for `BRICKED`, key `0xCA`, and step `+5`.
7. Extracting the protected CETRAINER from `CET_Archive.dat` for the MrAntiFun case.
8. Rerunning decoding and validating the result by size, hash, and XML structure.
9. Documenting confirmed facts and limitations.

I used AI as an auxiliary tool for code analysis, error diagnosis, and hypothesis testing. The work was iterative: I provided files and execution results, refined the task, evaluated the conclusions, and directed the investigation toward a reproducible result.

## 7. Limitations

- The conclusions apply to two specific samples, not to all Barracuda, MrAntiFun, or Cheat Engine trainers.
- The profiles `0xCB`, `0xCF`, `2A AD 2B 41`, `65 42 17 43 65`, and `65 42 17 43` come from the original project and must be attributed to AlexAltea.
- The parameters `0xCA`, step `+5`, and the `BRICKED` header were confirmed for the Watch Dogs sample under investigation; their prevalence in other trainers has not been established.
- Successful decompression alone is insufficient. Additional length and XML-structure checks are required.
- Before publication, retain links to the original implementations and check their licenses. Third-party executables and complete extracted tables should not be redistributed without checking the relevant rights.

## Sources

- [AlexAltea/cetrainer-unpacker](https://github.com/AlexAltea/cetrainer-unpacker)
- [Original Barracuda script](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/unpackers/unpack_cet_barracuda.py)
- [Original MrAntiFun script](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/unpackers/unpack_cet_mrantifun.py)
- [General CETRAINER documentation](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/docs/cetrainer.md)
- [Barracuda documentation](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/docs/cetrainer-barracuda.md)
- [MrAntiFun documentation](https://github.com/AlexAltea/cetrainer-unpacker/blob/master/docs/cetrainer-mrantifun.md)
