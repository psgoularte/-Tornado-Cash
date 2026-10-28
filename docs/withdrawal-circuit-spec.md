# Withdrawal circuit specification

This document specifies the withdrawal circuit (`src/circuit/`) before it is implemented. It covers US02 (generate the withdrawal proof) and US05 (bind the withdrawal to the recipient), and it is the reference for the circuit's negative tests. Items marked **D1–D4** are listed in [Open decisions](#open-decisions) and are not yet settled.

## Notation

- $\mathbb{F}_r$ is the BN254 scalar field, $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617$. All circuit values are elements of $\mathbb{F}_r$.
- $H(a, b)$ is `hash::hash2`: Poseidon of width 3 compatible with circomlib's `Poseidon(2)`, state $[0, a, b]$, output is the first element of the permuted state.
- $H_N$ is the function that computes the nullifier hash from the nullifier (**D1**).
- $d$ is the tree depth: 20 by default, configurable. Levels are indexed $i = 0, \dots, d-1$ from the leaf upward.

## Inputs

| Input | Visibility | Type | Meaning |
| --- | --- | --- | --- |
| `root` | public | $\mathbb{F}_r$ | Root of the deposit tree that the proof is made against |
| `nullifier_hash` | public | $\mathbb{F}_r$ | $H_N(\text{nullifier})$, recorded by the mixer to prevent double withdrawal |
| `recipient` | public | $\mathbb{F}_r$ | Who receives the amount (encoding: **D3**) |
| `relayer` | public | $\mathbb{F}_r$ | Who submits the withdrawal and receives the fee (0 if none; encoding: **D3**) |
| `fee` | public | $\mathbb{F}_r$ | Fee paid to the relayer (encoding: **D3**) |
| `nullifier` | private | $\mathbb{F}_r$ | Secret value of the note |
| `secret` | private | $\mathbb{F}_r$ | Secret value of the note |
| `siblings[0..d]` | private | $\mathbb{F}_r^{\,d}$ | Sibling node at each level of the leaf's path |
| `bits[0..d]` | private | $\{0, 1\}^d$, allocated as `Boolean` | Direction at each level: $b_i = 0$ if the current node is the left child, $1$ if it is the right child. The bits are the leaf index in binary, least significant bit first |

The public inputs are allocated in the order of the table. The verifier receives them in the same order.

## Constraints

Every constraint lists the story it serves, its cost in R1CS constraints and the negative tests that will cover it. A negative test builds a witness that is valid except for one tampered value, and checks that `cs.is_satisfied()` is `false`.

### C1 — Commitment (US01, US02)

The leaf is the commitment of the note: the hash of the nullifier and the secret.

$$h_0 = H(\text{nullifier}, \text{secret})$$

No equality is enforced here. $h_0$ is an intermediate value that C4 hashes up to the root, so a wrong note shows up as a root mismatch. Cost: one $H$.
Negative test: `us02_rejects_wrong_secret` (the right path and root, but a different secret).

### C2 — Nullifier hash (US02, US04)

The public nullifier hash is computed from the private nullifier, so the value the mixer records belongs to the note that was proven. Without C2, a withdrawer could present a fresh nullifier hash on every withdrawal and bypass US04.

$$\text{nullifier\_hash} = H_N(\text{nullifier})$$

Cost: one $H$ (if **D1** is a single `hash2` call) plus one equality constraint.
Negative tests: `us02_rejects_wrong_nullifier_hash` (the public value differs), `us02_rejects_wrong_nullifier` (the private nullifier differs, which also breaks C1 and C4).

### C3 — Direction bits are boolean (US02)

$$b_i \cdot (1 - b_i) = 0 \qquad i = 0, \dots, d-1$$

This is enforced by `Boolean::new_witness`: one constraint per bit. It is required for soundness. C4 selects the left node as $h_i + b_i(s_i - h_i)$. If $b_i$ could take any value, that expression could take any value, so the prover could hash an arbitrary pair at each level and "prove" membership of a note that is not in the tree.
Negative test: `us02_rejects_non_boolean_direction_bit`. It overwrites a bit's witness assignment with 2 after synthesis, because `Boolean` cannot hold 2.

### C4 — The path reaches the public root (US02)

Starting from the leaf, each level puts the current node and the sibling $s_i$ in order according to $b_i$, then hashes them:

$$l_i = h_i + b_i\,(s_i - h_i), \qquad r_i = h_i + s_i - l_i, \qquad h_{i+1} = H(l_i, r_i)$$

$$h_d = \text{root}$$

If $b_i = 0$, then $(l_i, r_i) = (h_i, s_i)$. If $b_i = 1$, then $(l_i, r_i) = (s_i, h_i)$. The product $b_i(s_i - h_i)$ costs one constraint and $r_i$ is linear, so its cost is zero (**D4**). Cost per level: one selection plus one $H$. One more constraint enforces $h_d = \text{root}$.
Negative tests: `us02_rejects_wrong_sibling`, `us02_rejects_flipped_direction_bit`, `us02_rejects_wrong_root` (the public root is not the root of the path), `us02_rejects_note_not_in_tree` (a valid-looking note whose commitment was never inserted).

### C5 — Recipient, relayer and fee are bound to the proof (US05)

$$\text{recipient}^2 = q_1, \qquad \text{relayer}^2 = q_2, \qquad \text{fee}^2 = q_3$$

$q_1, q_2, q_3$ are private witnesses that no other constraint uses. Cost: 3 constraints. These constraints hold for any value of the inputs, so no tampered witness can fail them, and the "invalid inputs do not satisfy the circuit" form of negative test does not apply here. US05 is tested at the proof level: a proof generated for one value must be rejected by `Groth16::verify` when the value is replaced. The tests are `us05_rejects_other_recipient`, `us05_rejects_other_relayer` and `us05_rejects_other_fee`.

## Why C5 is needed

A Groth16 verifier accepts a proof $(A, B, C)$ for public inputs $a_1, \dots, a_\ell$ (with $a_0 = 1$) when

$$e(A, B) = e(\alpha, \beta)\cdot e\Big(\textstyle\sum_{i=0}^{\ell} a_i\, \mathrm{IC}_i,\ \gamma\Big)\cdot e(C, \delta), \qquad \mathrm{IC}_i = \Big[\tfrac{\beta\, u_i(\tau) + \alpha\, v_i(\tau) + w_i(\tau)}{\gamma}\Big]_1 .$$

Here $u_i, v_i, w_i$ interpolate the coefficients of variable $i$ in the $A$, $B$ and $C$ matrices of the R1CS. If a public input appears in no constraint, its column is zero in all three matrices. Then $u_i = v_i = w_i = 0$, so $\mathrm{IC}_i$ is the point at infinity and $a_i \cdot \mathrm{IC}_i$ is the point at infinity for every $a_i$. The verification equation no longer depends on that input. Anyone who intercepts a valid proof can replace the recipient with their own address and the proof still verifies, which is exactly the attack US05 forbids.

Tornado Cash (`circuits/withdraw.circom`) closes this gap by squaring each of these inputs into an unused signal (`recipientSquare <== recipient * recipient`, and likewise for relayer, fee and refund). The constraint makes the input's column non-zero, so $\mathrm{IC}_i$ is no longer the point at infinity and changing $a_i$ invalidates the proof. A square is used rather than a linear constraint because circom's optimizer removes linear constraints. C5 is the same solution, without the refund, which this mixer does not have.

Note on our stack: ark-groth16 0.6 (`LibsnarkReduction`, `src/r1cs_to_qap.rs`) already appends one extra row per public input when building the QAP, as libsnark does. That row makes $u_i \neq 0$ even for unused inputs, which is why Tornado's own comment says the squares are "most likely not required". We still specify C5 for three reasons:

1. The binding becomes a property of our circuit instead of a detail of the reduction. That matters because this research may change the proof generation pipeline.
2. It costs 3 constraints (0.06% of the total).
3. It keeps the circuit comparable to Tornado's.

## Constraint estimate

The estimate uses the measured cost of `hash2` (240 constraints; `tests/poseidon_gadget.rs`) and the costs of the arkworks 0.6 gadgets: `Boolean::new_witness` is 1, a field multiplication is 1, `enforce_equal` is 1, and linear combinations are free.

| Part | Count | Cost each | Constraints |
| --- | --- | --- | --- |
| C1 commitment | 1 hash | 240 | 240 |
| C2 nullifier hash | 1 hash + 1 equality | 240 + 1 | 241 |
| C3 booleanity | $d = 20$ bits | 1 | 20 |
| C4 selection | $d = 20$ levels | 1 | 20 |
| C4 level hashes | $d = 20$ hashes | 240 | 4,800 |
| C4 root equality | 1 | 1 | 1 |
| C5 binding | 3 squares | 1 | 3 |
| **Total ($d = 20$)** | | | **5,325** |

In general the total is $(d + 2)\cdot 240 + 2d + 5 = 242d + 485$. Poseidon accounts for $22 \cdot 240 = 5{,}280$ constraints, or 99.2% of the total at $d = 20$.

Caveats:

- A `hash2` call with a constant input (possible under **D1**) may cost up to 3 constraints less, because a round-0 S-box on a constant is free.
- Using two `conditionally_select` calls per level instead of the formula in C4 would add 20 constraints (**D4**).
- The estimate must be confirmed by a test that asserts `cs.num_constraints()`, as `tests/poseidon_gadget.rs` does for `hash2`.

For the measurements (US07), the FFT domain has $242d + 485 + 6$ rows, where 6 is the instance variables (the constant 1 plus 5 public inputs) added by the reduction. That number is rounded up to a power of two: 4,096 for $d \le 14$, 8,192 for $15 \le d \le 31$ (including $d = 20$), and 16,384 from $d = 32$. The cost of the polynomial transforms therefore grows in steps with depth, while the cost of the MSMs grows linearly.

## Open decisions

These choices are not fixed by the user stories. Each one has a recommendation. None of them is decided yet.

### D1 — How to compute the nullifier hash with `hash2`

The nullifier hash is published at withdrawal. It must not be computable from, or equal to, the commitment published at deposit, or the two would be linked. Tornado gets this separation from Pedersen hashes of different input lengths: the commitment is Pedersen(nullifier ‖ secret) and the nullifier hash is Pedersen(nullifier). With a single two-input function, the options are:

- **A. $H(\text{nullifier}, 0)$.** The simplest option, and circomlib's `Poseidon(2)` test vectors still apply. There is no domain separation: it equals the commitment of the note $(\text{nullifier}, 0)$. The separation rests on the secret never being 0.
- **B. $H(T, \text{nullifier})$ with a constant tag $T$ derived from a fixed string.** Still the same function, so the same vectors apply. Separation is only probabilistic: it fails if some note has nullifier $T$.
- **C. A domain tag in the capacity element: state $[1, \text{nullifier}, 0]$ instead of $[0, a, b]$.** Commitments and tree nodes keep capacity 0. This is the domain separation method recommended by the Poseidon paper (Grassi et al., USENIX Security 2021). No choice of inputs can make the two initial states equal, so a collision between the domains is a collision of Poseidon itself. The circuit cost is the same, since the capacity is a constant.

**Recommendation: C.** Its separation is structural rather than probabilistic, and it costs no extra constraints. Cost of the choice: it adds `hash2` variants with a domain tag in `native` and `gadget`, and they need reference vectors from a cited source. circomlib's `PoseidonEx` takes an `initialState` input, and circomlibjs's reference implementation accepts an initial state, so cited vectors can be produced from them. If they cannot be obtained, fall back to B, which needs no new vectors.

Commitments and tree nodes share capacity 0 under all three options. That is safe because the depth is fixed: every accepted path has exactly $d$ hashes, so an internal node cannot be passed off as a leaf.

### D2 — Value of empty leaves

The tree is incremental, so the roots in the history are roots of trees whose unused leaves hold a fixed value $Z$. The property needed is that nobody knows a note $(n, s)$ with $H(n, s) = Z$. Otherwise anyone could prove membership of an empty leaf and withdraw without depositing.

- **Zero.** Under an ideal hash, 0 is as safe as any other value, but it is the value most likely to gain a known preimage by accident:
  - Without round constants, Poseidon maps $(0, 0)$ to $0$, because $0^5 = 0$ and $M \cdot 0 = 0$. A bug that drops the constants would therefore make $(0, 0)$ a valid note for every empty leaf.
  - 0 is also the default value of uninitialized storage (`Default::default()`, or Solidity storage), so an unset node would be indistinguishable from an empty one.
- **A "nothing up my sleeve" constant derived from a fixed public string.** Nobody chose it, so nobody can hold a preimage, and it has no algebraic structure. Tornado uses $Z = \text{keccak256}(\text{"tornado"}) \bmod r$ (`ZERO_VALUE` in tornado-core `contracts/MerkleTreeWithHistory.sol`).

**Recommendation:** reuse Tornado's value as is, hard-coded with a citation to its source:

$Z = 21663839004416932945382355908790599225266501822907911457504978515578255421292$ = `0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c`

The value was checked independently while writing this document, with a Keccak-256 implementation validated against the known digest of the empty string. It adds no dependency (no Keccak crate), and it comes from a cited source. The empty-subtree roots $Z_0 = Z$, $Z_{i+1} = H(Z_i, Z_i)$ are computed natively when the tree is created. They differ from Tornado's, which uses MiMC. The choice does not affect the circuit: siblings are ordinary witnesses.

### D3 — Encoding of recipient, relayer and fee

There is no blockchain, so the circuit only sees field elements.

**Recommendation:**

- Recipient and relayer are 20-byte identifiers (the size of an Ethereum address), mapped big-endian into $\mathbb{F}_r$. The mapping is injective because 160 < 254 bits.
- The fee is a `u64` mapped into $\mathbb{F}_r$.
- No range check in the circuit. Bit decomposition would cost about 254 constraints per value. The mixer checks $\text{fee} \le \text{amount}$ when accepting the withdrawal, as Tornado's contract does (`require(_fee <= denomination)`).

### D4 — Path selection gadget

Tornado's `DualMux` computes both outputs with a multiplication each, which costs 2 constraints per level. The formula in C4 computes $l_i$ with one multiplication and gets $r_i = h_i + s_i - l_i$ for free.

**Recommendation:** use the C4 formula. It saves $d$ constraints (20 at $d = 20$) and is covered by the same native/in-circuit path equivalence test.
