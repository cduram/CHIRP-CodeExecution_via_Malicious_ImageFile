# CHIRP — Arbitrary Code Execution via `eval()` in Kenwood ITM Driver

**Product:** CHIRP (all versions containing `chirp/drivers/kenwood_itm.py`)  
**Vendor:** kk7ds / CHIRP project — https://github.com/kk7ds/chirp  
**Confirmed on:** chirp-next-20260814 (commit cb7d5e2); code unchanged since 2012 
**Fixed on** Commit 39178db  
**CWE:** CWE-95 (Eval Injection)  

---

## Overview

CHIRP's Kenwood ITM file format driver passes raw CSV field values from an opened file directly to Python's built-in `eval()` with no validation. An attacker who delivers a crafted file to a CHIRP user achieves arbitrary code execution as the victim user.

## Root Cause

`chirp/drivers/kenwood_itm.py`, `_clean_tmode()`, lines 66–67:

```python
def _clean_tmode(self, headers, line, mem):
    rtone = eval(generic_csv.get_datum_by_header(headers, line, "TXSIG"))  # SINK
    ctone = eval(generic_csv.get_datum_by_header(headers, line, "RXSIG"))  # SINK
```

The TXSIG and RXSIG values come directly from a CSV row in the opened file. No type check, allowlist, or sandboxing is applied before `eval()`.

## POCs

Below are two POCs. 



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

---

## Impact

Any CHIRP user who opens a crafted file executes attacker-controlled Python code with their own OS-level privileges. No special conditions, elevated rights, or configuration are required. Viable delivery paths include:

- Email attachment
- Shared network drive (radio club, repeater group file shares)
- Download from a poisoned third-party source
- Repository containing radio frequency databases

Vector 2 is the higher-risk delivery: a `.img` file is the standard format CHIRP users exchange to share radio configurations. A victim opening what appears to be a peer's radio memory backup has no reason to distrust it.


## Disclosure

| Date | Event |
|---|---|
| 2026-08-17 | Both vectors discovered and runtime-confirmed |
| 2026-08-17 | POCs and disclosure report prepared |
| 2026-08-17 | Initial report sent to dsmith@danplanet.com |
| 2026-08-17 | Responded and fixed same day. https://github.com/kk7ds/chirp/commit/39178dbfc4fece083ab9ed20286d6ae3a91a718e

