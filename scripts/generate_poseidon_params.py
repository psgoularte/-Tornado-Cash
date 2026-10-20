#!/usr/bin/env python3
"""Generate src/hash/params.rs: Poseidon constants for width 3 (two inputs).

What it does
    Downloads circomlibjs' poseidon_constants.json at a pinned commit, checks
    its SHA-256 against the value recorded in the header of
    src/hash/params.rs (and stops with an error if they differ), and writes
    src/hash/params.rs with the round constants and the MDS matrix for t = 3,
    copied verbatim (same hex strings, same order). Nothing is computed: the
    script only copies values from the source file.

Source
    https://raw.githubusercontent.com/iden3/circomlibjs/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_constants.json
    (browsable at https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_constants.json)

Entries read
    C[1]: the 195 round constants for t = 3 (index t - 2 = 1), a flat array
          where C[r * 3 + i] is the constant for round r and state element i.
    M[1]: the 3x3 MDS matrix for t = 3.
    The round numbers (8 full, 57 partial) and the S-box exponent (5) are not
    in that file; they come from circomlib's circuits/poseidon_old.circom and
    are cited in the generated header.

Usage (from the repository root, Python 3.8+, standard library only)
    python scripts/generate_poseidon_params.py
    python scripts/generate_poseidon_params.py --source path/to/poseidon_constants.json

    With --source, a local copy is used instead of downloading; its SHA-256 is
    checked the same way. The output must be identical to the committed file:
    `git diff src/hash/params.rs` stays empty.
"""

import argparse
import hashlib
import json
import re
import sys
import urllib.request
from pathlib import Path

SOURCE_URL = (
    "https://raw.githubusercontent.com/iden3/circomlibjs/"
    "48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_constants.json"
)
PARAMS_RS = Path(__file__).resolve().parent.parent / "src" / "hash" / "params.rs"

WIDTH = 3
FULL_ROUNDS = 8
PARTIAL_ROUNDS = 57

HEADER = """\
//! Poseidon parameters for width 3 (two inputs) over the BN254 scalar field,
//! compatible with circomlib.
//!
//! Round numbers and S-box exponent: circomlib `circuits/poseidon_old.circom`
//! (`nRoundsF = 8`, `N_ROUNDS_P[t - 2]` = 57 for t = 3, `Sigma` computes x^5):
//! https://github.com/iden3/circomlib/blob/35e54ea21da3e8762557234298dbb553c175ea8d/circuits/poseidon_old.circom
//!
//! Round constants and MDS matrix: copied verbatim, in order, from circomlibjs
//! `src/poseidon_constants.json`, entries `C[1]` and `M[1]` (index t - 2 = 1):
//! https://github.com/iden3/circomlibjs/blob/48b3ab37013c5ed21e9ff8a80a5b010795c97094/src/poseidon_constants.json
//! (SHA-256 of that file: {sha256}).
//! circomlibjs states they were produced by the Poseidon authors' script
//! `generate_parameters_grain.sage` (hadeshash). The flat source array `C` is
//! grouped by round here: `C[r * 3 + i]` is `ROUND_CONSTANTS[r][i]`.
//!
//! Do not edit by hand.

use ark_bn254::Fr;
use ark_ff::MontFp;

/// State width t (one capacity element plus two inputs).
pub const WIDTH: usize = 3;
/// Number of full rounds (R_F), half before and half after the partial rounds.
pub const FULL_ROUNDS: usize = 8;
/// Number of partial rounds (R_P) for t = 3.
pub const PARTIAL_ROUNDS: usize = 57;
/// S-box exponent: x -> x^5.
pub const ALPHA: u64 = 5;
/// Total number of rounds.
pub const ROUNDS: usize = FULL_ROUNDS + PARTIAL_ROUNDS;
"""


def fail(message):
    sys.exit(f"error: {message}")


def recorded_sha256():
    """Read the expected SHA-256 from the header of the committed params.rs."""
    if not PARAMS_RS.exists():
        fail(f"{PARAMS_RS} not found; it holds the expected SHA-256 of the source")
    match = re.search(r"SHA-256 of that file: ([0-9a-f]{64})", PARAMS_RS.read_text())
    if match is None:
        fail(f"no recorded SHA-256 found in {PARAMS_RS}")
    return match.group(1)


def load_source(local_path):
    if local_path:
        return Path(local_path).read_bytes()
    with urllib.request.urlopen(SOURCE_URL, timeout=60) as response:
        return response.read()


def render(sha256, round_constants, mds):
    lines = [HEADER.replace("{sha256}", sha256)]
    lines.append("/// Round constants, one row of `WIDTH` per round.")
    lines.append("pub const ROUND_CONSTANTS: [[Fr; WIDTH]; ROUNDS] = [")
    for r in range(FULL_ROUNDS + PARTIAL_ROUNDS):
        lines.append("    [")
        for i in range(WIDTH):
            lines.append(f'        MontFp!("{round_constants[r * WIDTH + i]}"),')
        lines.append("    ],")
    lines.append("];")
    lines.append("")
    lines.append("/// MDS matrix; the linear layer computes `out[i] = sum_j MDS[i][j] * in[j]`.")
    lines.append("pub const MDS: [[Fr; WIDTH]; WIDTH] = [")
    for row in mds:
        lines.append("    [")
        for value in row:
            lines.append(f'        MontFp!("{value}"),')
        lines.append("    ],")
    lines.append("];")
    lines.append("")
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--source", help="local copy of poseidon_constants.json")
    args = parser.parse_args()

    expected = recorded_sha256()
    raw = load_source(args.source)
    actual = hashlib.sha256(raw).hexdigest()
    if actual != expected:
        fail(f"SHA-256 mismatch for the source file: expected {expected}, got {actual}")

    data = json.loads(raw)
    round_constants = data["C"][WIDTH - 2]
    mds = data["M"][WIDTH - 2]
    if len(round_constants) != WIDTH * (FULL_ROUNDS + PARTIAL_ROUNDS):
        fail(f"expected {WIDTH * (FULL_ROUNDS + PARTIAL_ROUNDS)} round constants, got {len(round_constants)}")
    if len(mds) != WIDTH or any(len(row) != WIDTH for row in mds):
        fail(f"expected a {WIDTH}x{WIDTH} MDS matrix")
    for value in round_constants + [v for row in mds for v in row]:
        if not re.fullmatch(r"0x[0-9a-f]{64}", value):
            fail(f"unexpected constant format: {value}")

    with open(PARAMS_RS, "w", newline="\n") as out:
        out.write(render(actual, round_constants, mds))
    print(f"wrote {PARAMS_RS} ({len(round_constants)} round constants, {WIDTH}x{WIDTH} MDS)")


if __name__ == "__main__":
    main()
