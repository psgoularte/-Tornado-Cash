# Withdrawal circuit specification

This document specifies the withdrawal circuit (`src/circuit/`) before it is implemented. It covers US02 (generate the withdrawal proof) and US05 (bind the withdrawal to the recipient), and it is the reference for the circuit's negative tests. Design choices that the user stories do not fix are recorded, with their justification, in [Decisions](#decisions) (D1–D4).

## Notation

- $\mathbb{F}_r$ is the BN254 scalar field, $r = 21888242871839275222246405745257275088548364400416034343698204186575808495617$. All circuit values are elements of $\mathbb{F}_r$.
- $H(a, b)$ is `hash::hash2`: Poseidon of width 3 compatible with circomlib's `Poseidon(2)`, state $[0, a, b]$, output is the first element of the permuted state.
- $H_N(n)$ is the nullifier hash: the same permutation and parameters, but with initial state $[1, n, 0]$. The capacity element 1 is the domain tag (D1).
- $d$ is the tree depth: 20 by default, configurable. Levels are indexed $i = 0, \dots, d-1$ from the leaf upward.

## Inputs

| Input | Visibility | Type | Meaning |
| --- | --- | --- | --- |
| `root` | public | $\mathbb{F}_r$ | Root of the deposit tree that the proof is made against |
| `nullifier_hash` | public | $\mathbb{F}_r$ | $H_N(\text{nullifier})$, recorded by the mixer to prevent double withdrawal |
| `recipient` | public | $\mathbb{F}_r$ | Who receives the amount: a 20-byte identifier, big-endian (D3) |
| `relayer` | public | $\mathbb{F}_r$ | Who submits the withdrawal and receives the fee: a 20-byte identifier, big-endian, or 0 if there is no relayer (D3) |
| `fee` | public | $\mathbb{F}_r$ | Fee paid to the relayer: a `u64` (D3) |
| `nullifier` | private | $\mathbb{F}_r$ | Secret value of the note |
| `secret` | private | $\mathbb{F}_r$ | Secret value of the note |
| `siblings[0..d]` | private | $\mathbb{F}_r^{\,d}$ | Sibling node at each level of the leaf's path |
| `bits[0..d]` | private | $\{0, 1\}^d$, allocated as field elements and constrained by C3 | Direction at each level: $b_i = 0$ if the current node is the left child, $1$ if it is the right child. The bits are the leaf index in binary, least significant bit first |

The public inputs are allocated in the order of the table. The verifier receives them in the same order.

## Constraints

Every constraint lists the story it serves, its cost in R1CS constraints and the negative tests that will cover it. A negative test builds a witness that is valid except for one tampered value, and checks that `cs.is_satisfied()` is `false`. The exception is C5, whose tests run at the verifier (see C5).

### C1 — Commitment (US01, US02)

The leaf is the commitment of the note: the hash of the nullifier and the secret.

$$h_0 = H(\text{nullifier}, \text{secret})$$

No equality is enforced here. $h_0$ is an intermediate value that C4 hashes up to the root, so a wrong note shows up as a root mismatch. Cost: one $H$.
Negative test: `us02_rejects_wrong_secret` (the right path and root, but a different secret).

### C2 — Nullifier hash (US02, US04)

The public nullifier hash is computed from the private nullifier, so the value the mixer records belongs to the note that was proven. Without C2, a withdrawer could present a fresh nullifier hash on every withdrawal and bypass US04.

$$\text{nullifier\_hash} = H_N(\text{nullifier})$$

Cost: one permutation, measured at 237 constraints (`tests/poseidon_gadget.rs`), plus one equality constraint. The state $[1, n, 0]$ has two constant elements, so two round-0 S-boxes are free.
Negative tests: `us02_rejects_wrong_nullifier_hash` (the public value differs), `us02_rejects_wrong_nullifier` (the private nullifier differs, which also breaks C1 and C4).

### C3 — Direction bits are boolean (US02)

$$b_i \cdot (1 - b_i) = 0 \qquad i = 0, \dots, d-1$$

The path gadget (`tree::gadget::compute_root`) enforces it explicitly, one constraint per bit, so the bits are allocated as plain field variables. Keeping the check inside the gadget means the C4 selection never depends on the caller having allocated `Boolean`s. C4 relies on it for soundness (see C4).
Negative test: `us02_rejects_non_boolean_direction_bit`. It allocates a bit with value 2 (or $-1$) directly.

### C4 — The path reaches the public root (US02)

Starting from the leaf, each level puts the current node and the sibling $s_i$ in order according to $b_i$, then hashes them:

$$l_i = h_i + b_i\,(s_i - h_i), \qquad r_i = h_i + s_i - l_i, \qquad h_{i+1} = H(l_i, r_i)$$

$$h_d = \text{root}$$

If $b_i = 0$, then $(l_i, r_i) = (h_i, s_i)$. If $b_i = 1$, then $(l_i, r_i) = (s_i, h_i)$. The product $b_i(s_i - h_i)$ costs one constraint, and $r_i$ is a linear combination, so it costs nothing (D4). Cost per level: one selection plus one $H$. One more constraint enforces $h_d = \text{root}$.

**This selection is sound only together with C3.** The formula yields one of the two ordered pairs only when $b_i \in \{0, 1\}$. For any other value of $b_i$ (and $s_i \neq h_i$), $l_i$ can be any field element, and $r_i = h_i + s_i - l_i$ follows it. The prover could then hash an arbitrary pair at each level and "prove" membership of a note that is not in the tree. C3 must never be removed or weakened while this selection is in use.

Negative tests: `us02_rejects_wrong_sibling`, `us02_rejects_flipped_direction_bit`, `us02_rejects_wrong_root` (the public root is not the root of the path), `us02_rejects_note_not_in_tree` (a valid-looking note whose commitment was never inserted).

### C5 — Recipient, relayer and fee are bound to the proof (US05)

$$\text{recipient}^2 = q_1, \qquad \text{relayer}^2 = q_2, \qquad \text{fee}^2 = q_3$$

$q_1, q_2, q_3$ are private witnesses that no other constraint uses. Cost: 3 constraints. These constraints hold for any value of the inputs, so no tampered witness can fail them. Following the project rule for such binding constraints (CLAUDE.md), their negative tests run at the verifier: a proof generated for one value must be rejected by `Groth16::verify` when that public input is replaced. The tests are `us05_rejects_other_recipient`, `us05_rejects_other_relayer` and `us05_rejects_other_fee`.

## Why C5 is needed

A Groth16 verifier accepts a proof $(A, B, C)$ for public inputs $a_1, \dots, a_\ell$ (with $a_0 = 1$) when

$$e(A, B) = e(\alpha, \beta)\cdot e\Big(\textstyle\sum_{i=0}^{\ell} a_i\, \mathrm{IC}_i,\ \gamma\Big)\cdot e(C, \delta), \qquad \mathrm{IC}_i = \Big[\tfrac{\beta\, u_i(\tau) + \alpha\, v_i(\tau) + w_i(\tau)}{\gamma}\Big]_1 .$$

Here $u_i, v_i, w_i$ interpolate the coefficients of variable $i$ in the $A$, $B$ and $C$ matrices of the R1CS. If a public input appears in no constraint, its column is zero in all three matrices. Then $u_i = v_i = w_i = 0$, so $\mathrm{IC}_i$ is the point at infinity and $a_i \cdot \mathrm{IC}_i$ is the point at infinity for every $a_i$. The verification equation no longer depends on that input. Anyone who intercepts a valid proof can replace the recipient with their own address and the proof still verifies, which is exactly the attack US05 forbids.

Tornado Cash (`circuits/withdraw.circom`) closes this gap by squaring each of these inputs into an unused signal (`recipientSquare <== recipient * recipient`, and likewise for relayer, fee and refund). The constraint makes the input's column non-zero, so $\mathrm{IC}_i$ is no longer the point at infinity and changing $a_i$ invalidates the proof. A square is used rather than a linear constraint because circom's optimizer removes linear constraints. C5 is the same solution, without the refund, which this mixer does not have.

Note on our stack: ark-groth16 0.6 (`LibsnarkReduction`, `src/r1cs_to_qap.rs`) already appends one extra row per public input when building the QAP, as libsnark does. That row makes $u_i \neq 0$ even for unused inputs, which is why Tornado's own comment says the squares are "most likely not required". We keep C5 anyway, for three reasons:

1. The binding becomes a property of our circuit instead of a detail of the reduction. That matters because this research may change the proof generation pipeline.
2. It costs 3 constraints (0.06% of the total).
3. It keeps the circuit comparable to Tornado's.

## Constraint estimate

The estimate uses measured costs: `hash2` costs 240 constraints and $H_N$ costs 237 (`tests/poseidon_gadget.rs`). One path level costs 242: 240 for the hash, 1 for the selection and 1 for the boolean bit (`tests/path_gadget.rs`). It also uses the costs of the arkworks 0.6 gadgets: a field multiplication is 1, `enforce_equal` is 1, and linear combinations are free.

| Part | Count | Cost each | Constraints |
| --- | --- | --- | --- |
| C1 commitment | 1 hash | 240 | 240 |
| C2 nullifier hash | 1 $H_N$ + 1 equality | 237 + 1 | 238 |
| C3 booleanity | $d = 20$ bits | 1 | 20 |
| C4 selection | $d = 20$ levels | 1 | 20 |
| C4 level hashes | $d = 20$ hashes | 240 | 4,800 |
| C4 root equality | 1 | 1 | 1 |
| C5 binding | 3 squares | 1 | 3 |
| **Total ($d = 20$)** | | | **5,322** |

In general the total is $(d + 1)\cdot 240 + 237 + 2d + 5 = 242d + 482$. Poseidon accounts for $21 \cdot 240 + 237 = 5{,}277$ constraints, or 99.2% of the total at $d = 20$.

The parts are measured, but the total must still be confirmed by a test that asserts `cs.num_constraints()` on the full circuit, once the circuit exists.

### Observation for the measurement phase: FFT domain

The QAP reduction adds one row per instance variable (the constant 1 plus the 5 public inputs) to the R1CS constraints. At $d = 20$ that is about $5{,}322 + 6 = 5{,}328$ rows. The evaluation domain is the next power of two, **8,192**, so about 35% of the domain (2,864 rows) is padding, and the polynomial transforms work on 8,192 points regardless.

In general the domain has $242d + 488$ rows rounded up to a power of two:

| Depth | Domain size |
| --- | --- |
| $d \le 14$ | 4,096 |
| $15 \le d \le 31$ (including $d = 20$) | 8,192 |
| $d \ge 32$ | 16,384 |

So the cost of the transforms should grow in steps with depth, while the MSM cost, which follows the number of variables, should grow linearly. The measurements (US07) should check both predictions, and should record the domain size alongside the constraint count on each CSV row.

## Decisions

These choices are not fixed by the user stories. They were decided after review of the first version of this document.

### D1 — Nullifier hash: domain tag in the capacity element

**Decision:** $H_N(n)$ is the Poseidon permutation of width 3 applied to the initial state $[1, n, 0]$, and its output is the first element of the result. Commitments and tree nodes keep capacity 0 ($H$).

**Justification:**

- **Unlinkability.** The nullifier hash is published at withdrawal. It must not be computable from, or equal to, the commitment published at deposit, or the two would be linked. Tornado gets this separation from Pedersen hashes of different input lengths: the commitment is Pedersen(nullifier ‖ secret) and the nullifier hash is Pedersen(nullifier).
- **Rejected alternatives.** With a single two-input function there were two other options:
  - $H(n, 0)$ has no separation at all: it equals the commitment of the note $(n, 0)$.
  - $H(T, n)$ with a constant tag $T$ separates the domains only probabilistically: it fails if some note has nullifier $T$.
- **Why the capacity tag.** Tagging the capacity element is the domain separation method recommended by the Poseidon paper (Grassi et al., USENIX Security 2021). No choice of inputs can make $[1, a, b]$ equal to $[0, a', b']$, so a collision between the two domains is a collision of Poseidon itself. The tag is a constant, so it adds no constraints.

**Implementation requirements**, applied when the circuit is implemented:

- Add the tagged variant to both `hash::native` and `hash::gadget`, with a native/in-circuit equivalence test.
- Take the reference vectors from circomlibjs, computed with an initial state, and pin the source link to a commit.
- If trustworthy vectors cannot be obtained, stop, report it, and fall back to $H(T, n)$, which can reuse circomlib's `Poseidon(2)` vectors.

**Note:** commitments and tree nodes share capacity 0. That is safe because the depth is fixed: every accepted path has exactly $d$ hashes, so an internal node cannot be passed off as a leaf.

### D2 — Empty leaves: Tornado's constant

**Decision:** empty leaves hold $Z = \text{keccak256}(\text{"tornado"}) \bmod r$, the constant `ZERO_VALUE` in tornado-core `contracts/MerkleTreeWithHistory.sol`. It is hard-coded with a citation to that source:

$Z = 21663839004416932945382355908790599225266501822907911457504978515578255421292$ = `0x2fe54c60d3acabf3343a35b6eba15db4821b340f76e741e2249685ed4899af6c`

The roots of empty subtrees are $Z_0 = Z$ and $Z_{i+1} = H(Z_i, Z_i)$, computed natively when the tree is created. They differ from Tornado's, which uses MiMC.

**Justification:**

- **The required property.** The roots in the history are roots of trees whose unused leaves hold $Z$. Nobody may know a note $(n, s)$ with $H(n, s) = Z$, or anyone could prove membership of an empty leaf and withdraw without depositing.
- **Why not zero.** Under an ideal hash, 0 is as safe as any other value, but it is the value most likely to gain a known preimage by accident:
  - Without round constants, Poseidon maps $(0, 0)$ to $0$, because $0^5 = 0$ and $M \cdot 0 = 0$.
  - 0 is the default value of uninitialized storage, so an unset node would be indistinguishable from an empty one.
- **Why a constant from a fixed string.** Nobody chose it, so nobody can hold a preimage, and it has no algebraic structure.
- **Why reuse Tornado's.** It comes from a cited source and adds no dependency (no Keccak crate). The value above was checked independently while writing this document, with a Keccak-256 implementation validated against the known digest of the empty string.
- **No effect on the circuit:** siblings are ordinary witnesses.

### D3 — Encoding of recipient, relayer and fee

**Decision:**

- Recipient and relayer are 20-byte identifiers (the size of an Ethereum address), mapped big-endian into $\mathbb{F}_r$. Relayer 0 means "no relayer".
- The fee is a `u64` mapped into $\mathbb{F}_r$.
- The circuit has no range checks. The mixer rejects a withdrawal whose fee exceeds the deposit amount ($\text{fee} \le \text{amount}$).

**Justification:**

- There is no blockchain, so the circuit only sees field elements, and all it has to do is bind them (C5).
- Both mappings are injective, because 160 and 64 bits are fewer than 254 bits, so distinct values stay distinct in the field.
- A range check in the circuit would need a bit decomposition of about 254 constraints per value, for a property the mixer can check directly. Tornado's contract does the same: `require(_fee <= denomination)`.

### D4 — Path selection with one multiplication

**Decision:** compute $l_i = h_i + b_i(s_i - h_i)$ with one multiplication and $r_i = h_i + s_i - l_i$ as a linear combination, as specified in C4.

**Justification:**

- Tornado's `DualMux` computes both outputs with a multiplication each, which costs 2 constraints per level. This formula saves $d$ constraints (20 at $d = 20$).
- It is covered by the native/in-circuit path equivalence test.
- **It depends on C3:** with a non-boolean $b_i$, the selection lets the prover choose the hashed pair freely (see C4). C3 is therefore a soundness requirement of D4, not only a type check.
