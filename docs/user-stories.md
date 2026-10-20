# User stories — Tornado Cash-style mixer

Oct 19, 2026 · @Pedro

## Context and scope

This document defines what the mixer must do before any line of code is written. It is the deliverable of the first task in the research schedule and the basis for the tests: every acceptance criterion becomes at least one automated test.

The goal of the research is to identify, through profiling, the bottleneck in generating the withdrawal proof of a Tornado Cash-style mixer and to reduce it with a measured optimization. The mixer is implemented from scratch in Rust, without a blockchain: the role of the smart contract is simulated in memory.

**Fixed parameters**

| Item              | Choice             | Note                                                                      |
| ----------------- | ------------------ | ------------------------------------------------------------------------- |
| Proof system      | Groth16            | The same as Tornado Cash                                                  |
| Curve             | BN254              | The same as Tornado Cash and Ethereum                                     |
| Hash function     | Poseidon           | The original Tornado uses Pedersen and MiMC; the swap is a stated simplification |
| Tree depth        | 20 (configurable)  | The same as Tornado Cash; other depths only in the measurements           |
| Deposit amount    | Single and fixed   | As in each Tornado Cash pool                                              |
| Root history      | 30 roots           | The same number used by the Tornado Cash contract                         |

**Out of scope:** blockchain and smart contracts, relayer network, graphical interface, wallet and key management, variable amounts, and analysis of the anonymity provided by the mixer.

## Actors and glossary

**Actors**

- **Depositor:** whoever puts the amount into the mixer and keeps the secret note.
- **Withdrawer:** whoever withdraws the amount to a recipient, proving they hold a valid note. Usually the same depositor, using another address.
- **Mixer:** the system that keeps the deposit tree and the nullifier registry, and accepts or rejects withdrawals. It plays the role of the smart contract.
- **Researcher:** whoever measures proof generation performance.

**Glossary**

| Term               | Meaning                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------- |
| Note               | Pair of secret values (nullifier and secret) known only to the depositor                                         |
| Commitment         | Hash of the note; it is what becomes public in the tree                                                          |
| Nullifier          | Secret value of the note whose hash is revealed at withdrawal, to prevent double spending without revealing which deposit was used |
| Nullifier hash     | Public value recorded by the mixer for each accepted withdrawal                                                  |
| Deposit tree       | Merkle tree whose leaves are the commitments                                                                     |
| Root               | Hash at the top of the tree; it changes with every deposit                                                       |
| Path               | Sibling nodes linking a leaf to the root                                                                         |
| Withdrawal proof   | Zero-knowledge proof that the withdrawer knows a note whose commitment is in the tree, without revealing which   |

## Mixer stories

### US01 — Deposit

_As a depositor, I want to generate a secret note and record its commitment in the tree, so that I can withdraw later without revealing which deposit is mine._

- The note is generated with a cryptographically secure random number generator.
- The commitment is the Poseidon hash of the nullifier and the secret.
- The commitment goes into the next free leaf, and the new root is recorded in the history.
- A commitment already in the tree is rejected.
- When the tree is full, the deposit is rejected.

### US02 — Generate the withdrawal proof

_As a withdrawer, I want to generate a proof that I know a note in the tree, without revealing which one, in order to withdraw the amount._

- The public inputs are the root, the nullifier hash, the recipient, the relayer and the fee.
- The private inputs are the nullifier, the secret and the leaf path.
- For a valid note, the proof is generated and accepted by the verifier.
- For a note that is not in the tree, or with a wrong path or nullifier, the circuit is not satisfied.

### US03 — Withdraw

_As the mixer, I want to accept a withdrawal only if the proof is valid, the root is known and the nullifier has never been used, so that no one withdraws without having deposited._

- Valid proof, known root and new nullifier: withdrawal accepted and nullifier hash recorded.
- Tampered proof: withdrawal rejected.
- Root not in the history: withdrawal rejected.

### US04 — Prevent double withdrawal

_As the mixer, I want to reject a second withdrawal with the same note, so that each deposit is withdrawn only once._

- A withdrawal with an already recorded nullifier hash is rejected, even with a new, valid proof.
- The same holds if the second proof uses another root from the history.

### US05 — Bind the withdrawal to the recipient

_As a withdrawer, I want my proof to be valid only for the recipient I chose, so that no one can intercept the proof and change where the amount goes._

- A proof generated for one recipient is rejected if presented with another recipient.
- The same holds for the relayer and the fee.

### US06 — Accept recent roots

_As a withdrawer, I want my proof to remain valid even if new deposits happen while it is being generated, so that I do not need to generate it again._

- The mixer keeps the last 30 roots.
- A proof made against a root still in the history is accepted.
- A proof made against a root that has left the history is rejected.

## Research stories

### US07 — Measure the time of each proof step

_As a researcher, I want the time of each step of withdrawal proof generation, in order to identify the bottleneck._

- The measured steps are constraint synthesis, witness computation, polynomial transforms and each multi-scalar multiplication.
- The sum of the step times differs by less than 5% from the total measured time.
- Tree depth and number of threads are configurable without changing code.
- Results are written to CSV, with the configuration used on each row.

### US08 — Reproduce the measurements

_As a researcher, I want to reproduce all measurements with a single command, so that others can confirm the paper's results._

- A single command runs every configuration of the measurement protocol.
- The parameters of each experiment are versioned in the repository.
- The README describes the machine used and the steps to repeat the experiments.

### US09 — Compare the optimized version with the original

_As a researcher, I want to compare time and memory of both versions under the same conditions, in order to measure the gain from the optimization._

- Both versions generate proofs accepted by the same verifier.
- Both versions are measured with the same configurations and the same number of repetitions.
- The result shows mean and confidence interval of time and memory for each version.

## Traceability

Each story is delivered by schedule tasks and demonstrated by tests. Test names in the code carry the story identifier (for example, `us04_rejects_repeated_nullifier`), so that coverage can be checked.

| Story                             | Schedule tasks                                                    | Period      |
| --------------------------------- | ----------------------------------------------------------------- | ----------- |
| US01 — Deposit                    | Poseidon hash, deposit tree, deposit and withdrawal simulation    | 10/20–11/12 |
| US02 — Generate withdrawal proof  | Path verification in the circuit, withdrawal circuit, proof generation | 11/03–11/10 |
| US03 — Withdraw                   | Deposit and withdrawal simulation, flow test                      | 11/11–11/13 |
| US04 — Prevent double withdrawal  | Deposit and withdrawal simulation, flow test                      | 11/11–11/13 |
| US05 — Bind to recipient          | Withdrawal circuit, circuit test                                  | 11/04–11/06 |
| US06 — Accept recent roots        | Deposit and withdrawal simulation, flow test                      | 11/11–11/13 |
| US07 — Measure each step          | Measurement protocol, instrumentation, measurements               | 11/16–11/27 |
| US08 — Reproduce measurements     | Repository preparation for reproduction                           | 01/27–01/28 |
| US09 — Compare versions           | Optimized version test, final measurements, statistics            | 12/14–01/22 |
