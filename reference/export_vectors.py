# SPDX-License-Identifier: Apache-2.0
"""Exports every spec test vector as machine-readable reference/vectors.json.

Imports the two generators (which self-validate against RFC 7748 and the
official cacophony vector, respectively) so the JSON can never drift from
what they compute. Output is deterministic: same inputs, byte-identical file.

Requires: pip install cryptography (via vectors_handshake)
"""
import json
import sys
from pathlib import Path

HERE = Path(__file__).parent
sys.path.insert(0, str(HERE))

import vectors_address
import vectors_handshake

SPEC_VERSION = "0.4.0-draft"


def main():
    data = {
        "spec_version": SPEC_VERSION,
        "generated_by": ["reference/vectors_address.py", "reference/vectors_handshake.py"],
        "license": "CC0-1.0",
        "vectors": {**vectors_address.vectors(), **vectors_handshake.vectors()},
    }
    out = HERE / "vectors.json"
    out.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n")
    print(f"wrote {out} ({out.stat().st_size} bytes, {len(data['vectors'])} vector groups)")


if __name__ == "__main__":
    main()
