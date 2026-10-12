# FortID CTF 2026 — solutions

Compact solution paths reconstructed from contemporaneous notes; they have not been independently rerun. Flags, live-target details, exploit payloads, and identity-linked OSINT answers are omitted. Missing routes are not guessed. AI assistance was used despite the event rules prohibiting it.

- **Baby Crypto** — Pipelined inserts reused a CTR nonce. XOR the resulting ciphertexts to cancel the shared keystream, then use known or controlled plaintext to recover the protected text.
- **Baby Misc** — The ZIP entry paths encoded a character sequence. Reassemble characters from the paths in archive order.
- **Baby Pwn** — A freed draft left a stale reference. Reuse the freed slot so that the stale reference reaches the challenge's win path.
- **Bounty Hunter** — The verifier checked commitment and fold equalities but failed to enforce the polynomial/folding soundness conditions. A forged low-degree proof chain therefore passed the incomplete checks.
- **Checksum** — Fingerprint the call graph in preorder, divide it into fixed-size call blocks, and XOR each block's immediate values to recover output bytes. Validate the partition against the exposed selector checks.
- **Cubism** — Encode silhouette compatibility as SAT constraints, then minimize voxel count with a MILP objective under the puzzle's cap. The resulting minimum shape passes the QR-compatible checks.
- **DESBox** — Use 3DES's complementation property: complementing the keys complements the corresponding ciphertext. Align shuffled layouts by their single outlier byte, then apply the complement relation to decrypt.
- **Doctor Bye Bye** — The sort expression permits a SQLite ordering injection. Turn first-row order into a boolean oracle, then binary-search the protected note.
- **Do You Know Lika?** — Recursive theme merging polluted inherited template properties; the print worker then dynamically compiled attacker-controlled Handlebars structure. The resulting template-context escape reached data outside the intended postcard context.
- **End of Life** — DOS text input treats Ctrl-Z as EOF, while the parser trusts an unchecked scanset. Use the EOF behavior to reach the overflowing parse path and redirect execution.
- **EU Gift** — Recognize the reference to the Norway Problem: Erlang is the intended answer.
- **Flag from the Future** — Recover the cell grid from the screenshot, render candidate text with DejaVu Sans Mono Bold at the matching size, and forward-simulate Conway's Life. The matching image used 18 generations.
- **Fortune Teller** — The program passes the question directly to `printf`, with attacker-controlled data available as variadic arguments. Use the disclosure to locate control data, then a bounded format-string write redirects the return path to the built-in win routine.
- **GDB SaaS** — The function-name input can alter GDB's disassembly command. Its source-interleaving mode follows DWARF line records, whose compile-time filename mapping exposes a file from the build context.
- **Human RNG** — The QR keystream is the final 1,681 bits of the human-generated stream. Score candidate QR reconstructions against the observed stream's anti-persistent transition bias, then decode the best-supported image.
- **King Admin** — A stored announcement reaches an admin preview, and its CSP nonce is predictable from a small public hint set. The stored-script path crosses the issuer's trust boundary into the credential-verification flow.
- **Sticker Booth** — A row-boundary error causes a zero-only overwrite into pooled-object metadata. A stale alias then permits reuse of the freed chunk as another object type, crossing from memory corruption into the challenge's privileged print path.
- **Sticky Headers** — The gateway and backend disagree about duplicate message lengths. Desynchronize them to reach the internal staff preview; its template-rendered message then exposes the protected local content.
- **String Peek and Poke** — Unchecked string indexing reaches adjacent C++ iostream locale state. Use the read/write primitive to disclose the bundled runtime and corrupt the character facet's virtual dispatch, redirecting later input handling into a process-launch path.
- **Ultimative PHP** — PHP normalizes dotted request keys differently from the raw-query access check; array-to-string conversion and loose numeric-string comparison also defeat the legacy recovery checks. The accepted serialized profile then reaches the challenge's include/write path.
