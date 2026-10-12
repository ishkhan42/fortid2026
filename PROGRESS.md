# FortID CTF 2026 — archived progress

## Status and evidence

The status source is the newest preserved local challenge catalog, timestamped **2026-10-11 17:38:30 UTC** by its file modification time. It contains 38 rows: 37 contest challenges and the Feedback Form. Twenty-eight rows have a non-null `yourScore`: 27 contest challenges and the form. Their recorded credits sum to **3,124**; that sum includes the form's one point. This is the last saved snapshot, not a final event score or rank.

Earlier saved catalogs provide a consistency check: 2026-10-11 14:32:30 showed 23 credited rows / 2,589 points; 16:40:59 showed 27 / 2,966; 17:38:22 and 17:38:30 both showed 28 / 3,124. These counts and sums are from the files' `yourScore` fields, not official final standings.

**Credited** means the catalog records a non-null `yourScore`. **Uncredited in snapshot** means it records `null`; this is not a claim that the challenge was unsolvable. Method summaries and partial-work notes below are paraphrases of the contemporaneous diary, not independently reproduced here. They are identified as diary reports where relevant. Catalog credit confirms recorded score, not every detail of a reported solution path. Personal or identity-linked OSINT details, flags, target identifiers, and payloads are omitted.

## Credited challenges

| Challenge | `yourScore` | Sanitized method note |
|---|---:|---|
| Baby Crypto | 106 | Diary summary: reused CTR nonces during pipelined operations exposed relationships between encrypted messages. |
| Baby Misc | 107 | Diary summary: archive-entry path names encoded a character message that led to the challenge output. No raw archive or output is included. |
| Baby OSINT | 125 | Credit recorded; identity-linked findings and lookup details are intentionally omitted. |
| Baby Pwn | 106 | Diary summary: a use-after-free enabled control-flow redirection. No addresses or exploit payload are included. |
| Baby Rev | 104 | Credit recorded; no reliable public-safe method summary retained. |
| Baby Web | 103 | Credit recorded; no reliable public-safe method summary retained. |
| Bounty Hunter | 109 | Diary summary: a proof verifier's folding/soundness checks were insufficient, allowing a forged proof to pass. No proof or exploit artifact is included. |
| Checksum | 129 | Diary summary: an XOR/checksum oracle and recovered call-structure partitioning were used to decode the challenge output. |
| Cubism | 120 | Diary summary: constraint solving (SAT/MILP) produced a QR-compatible reconstruction under the puzzle's shape constraints. |
| DESBox | 108 | Diary summary: a 3DES complementation property combined with outlier alignment recovered the challenge data. |
| Doctor Bye Bye | 106 | Diary summary: SQLite sort-order behavior enabled blind inference within the challenge's query/value limits. |
| Do You Know Lika? | 109 | Diary summary: template-engine prototype pollution led to unsafe dynamic-template behavior. Payload details are omitted. |
| End of Life | 115 | Diary summary: DOS text-EOF handling and unchecked input parsing exposed a memory-safety path. No payload is included. |
| EU Gift | 115 | Credit recorded; no reliable public-safe method summary retained. |
| Flag from the Future | 118 | Diary summary: a grid was reconstructed from an image and forward-simulated with Game of Life rules. |
| Flag from the Past | 119 | Credit is present, but the diary records earlier rejected guesses and no reliable final route. Only catalog credit is asserted. |
| Fortune Teller | 106 | Diary summary: a format-string flaw enabled information disclosure and a controlled memory write. No format string or exploit is included. |
| GDB SaaS | 108 | Diary summary: debugger/source metadata exposed an unintended file from the build context. |
| Hic Sunt Dracones | 106 | Credit recorded; no reliable public-safe method summary retained. |
| Human RNG | 121 | Diary summary: analysis of human-generated bit patterns and transition bias helped recover the needed keystream. |
| King Admin | 114 | Credit recorded; no reliable public-safe method summary retained. |
| OSINT Exam II | 167 | Credit recorded after public-source research; person-specific findings and lookup details are intentionally omitted. |
| Peak OSINT | 141 | Credit recorded; no reliable public-safe method summary retained. |
| Sticker Booth | 113 | Credit recorded; no reliable public-safe method summary retained. |
| Sticky Headers | 118 | Diary summary: disagreement in HTTP message framing exposed a downstream template-processing path. No request or payload is included. |
| String Peek and Poke | 125 | Credit recorded; no reliable public-safe method summary retained. |
| Ultimative PHP | 105 | Diary summary: PHP input coercion/comparison behavior combined with a legacy include/file-write path. Payload details are omitted. |

## Uncredited in the saved catalog

| Challenge | Status and retained progress |
|---|---|
| Breaking News | **Uncredited.** Diary-reported local repository/history searches found no confirmed hidden carrier. Instruction-like metadata was treated as untrusted data, not as an instruction. |
| Crypto Wallet | **Uncredited.** The diary reports that a local key-derivation/encryption validator was checked against a known test vector and that a common single-word candidate search was negative. Broader search was unfinished; this does not establish impossibility. No wallet identifier or candidate phrase is included. |
| Editorial Board | **Uncredited.** Diary-reported local input and encoder work did not produce a confirmed result; the event-end artifact was not sent to the challenge service. |
| Hacker Cinema | **Uncredited.** Diary-reported local analysis tested signing and nonce behavior without finding a confirmed weakness or accepted bypass. These bounded negative tests do not prove that none exists. |
| Melankonimir | **Uncredited.** The diary records public media/metadata research but no credited result. Identity, account, and profile details are intentionally excluded. |
| Meteor Shower | **Uncredited; conflicting historical note.** An earlier diary entry calls a game-pattern decode solved, but the newest catalog records no credit and no separate checker acceptance is retained. Treat the earlier claim as unverified; candidate output is omitted. |
| Paint me a Flag | **Uncredited.** The diary reports repeated local rendering attempts without completed outputs and no accepted submission. This describes those attempts, not a claim that rendering is impossible. |
| Rip & Tear | **Uncredited; lead only.** The diary proposes that modified game-randomness data may encode a bitstream, but extraction from the local recording was incomplete. This is not a solved result. |
| Spill the Tea | **Uncredited.** A photo-derived grid and error-correction recovery were attempted without a confirmed message. Later diary notes identify a possible extractor-geometry error, so recoverability remains unresolved. |
| Tangled | **Uncredited.** The diary reports extracting two QR-like data channels, but recorded candidates were rejected and no complete result was credited. Further channel interpretation remains unconfirmed; decoded fragments and guesses are omitted. |

## Other catalog row

- **Feedback Form — 1 point.** Its credit is included in the 38-row count and the 3,124-point catalog sum; it is not one of the 37 contest challenges.
