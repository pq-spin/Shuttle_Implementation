# SHUTTLE Python reference (P12)

Independent, pure-Python (stdlib only) mirror of the deterministic,
KAT-load-bearing layers of the SHUTTLE signature scheme, plus the byte-exact
cross-checks against the C reference (`SHUTTLE/ref/`). The C ref is the
oracle; the Python ref leads it for correctness review and is asserted
byte-for-byte equal. A divergence is a bug.

## Modules (the mirrors)

| file | mirrors | what it proves |
|---|---|---|
| `params.py` | `ref/params.h`, `ref/reduce.h` | per-set constant table; `pk/sk` sizes, `ZETA^n=-1`, `n*NINV=1`, `H_h` integer |
| `reduce_ref.py` | `ref/reduce.{h,c}` | `montgomery_reduce16`/`fqmul16`/`addm16`/`subm16` + `reduce32`/`freeze`/`reduce_mod_2q` |
| `ntt_ref.py` | `ref/ntt/<qset>/ntt_ref.c` | complete CT/GS NTT; `ntt->pointwise->invntt_tomont == schoolbook` |
| `packing_ref.py` | `ref/packing.c` | `integer/poly_to_bytes` (LSB-first), `bytes_to_bits` (MSB-first, K3), `pack_pk/sk/com`, `encode_com_vec` (MS-A7) |
| `drng_ref.py` | `ref/drng.c` | SM3 Hash-DRBG (`init/get_random_number`); SM3("abc") KAT |
| `rans_ref.py` | `ref/rans.c` (via `tools/rans.py`) | SHUTTLE block-plan rANS encode/decode + re-encode equality (K15) |
| `sampler_ref.py` | `ref/sampler.c`, `ref/sampler_u.c` | `cdt_scan96` (96-bit 3x32 limb, borrow-fold), `sampler_u` (MSB-first 80-bit CLZ + 57-bit mantissa + Q62 ApproxLog) |
| `gauss_ref.py` | `ref/approx_exp.h`, `ref/sampler.c`, `ref/polyvec.c` | ApproxExp Q64 kernel (deg-8 Horner + 7 squarings), `gauss_finalize` zero-fold, the SampleY/ExpandS mini-batch byte schedule (sign/padding prefix plus fold bytes, K6/K8/K9) |
| `rounding_ref.py` | `ref/rounding.c` | CompressY/StretchS/RoundB, mod-2q lift (K13), MakeHint/UseHint, `mat_mul_2q`/`mat_mul_z1_2q` (NTT-domain), the centered-sqnorm gates |
| `irs_ref.py` | `ref/irs.c`, `ref/sampler_u.c` | `sampler_u_decode` (18-byte block), the `u_q44` form (2 r^2 ln2, K12), `R_transition` (sign-normalize + 15 boundary pairs), `reject_sample` (single bulk `tau*18` buffer, ascending-j, K2/K3/K5) |
| `xof_ref.py` | `ref/symmetric.c`, `ref/xof.h`, `ref/polyvec.c` | the XOF layer (SHA3_MODE SHAKE128/256 via `hashlib`; NGCC_MODE SM3 DRBG) + the `uniform_stream`/`gauss_stream` one-squeeze-per-fill engines |
| `sign_ref.py` | `ref/sign.c`, `ref/polyvec.c`, `ref/packing.c` | full `keygen`/`sign`/`verify`: ExpandSeeds/SigningSeeds/A/S, SampleC/Y, the kappa timing (K4), the cached-matrix wiring, `pack_sig`(_raw)/`unpack_sig`(_raw) |

`sampler_ref.py` parses the committed `tools/rcdt_tables.h` (RCDT tables) and
`tools/approx_log_poly.h` (Q62 log2 coeffs); `gauss_ref.py` parses
`tools/approx_exp_poly.h` (Q64 exp coeffs); `rounding_ref.py` parses
`tools/rounding_consts.h` (round-to-nearest reciprocals); `irs_ref.py` parses
`ref/irs.c` (the `R2LN2_QF`/`R2LN2_QSHIFT` constant) -- no re-derivation, so
they read the SAME integers the C does.

## Cross-checks (Python == C, byte-exact)

| file | C oracle | coverage |
|---|---|---|
| `xcheck.py` + `xcheck_dump.c` | reduce/poly/poly_ntt/packing/drng | DRNG draws, `reduce32/freeze/reduce_mod_2q`, NTT fwd+inv, `pk/sk/com` |
| `xcheck_rans.py` + `rans_oracle.c` | `shuttle_rans_encode` | `rans_ref == committed golden == C` on real response vectors + round-trip + re-encode |
| `xcheck_sampler.py` + `sampler_oracle.c` | `sampler_sigma2`/`sampler_u` | `cdt_scan96` byte-exact; `sampler_u` (a,frac) byte-exact from raw 18-byte stream |
| `xcheck_sign.py` + `sign_dump.c` | `crypto_sign_keypair_xi`/`crypto_sign_signature_rnd`/`crypto_sign_verify` | **end-to-end**: Python `pk`/`sk`/`sig` == C ref BYTE-FOR-BYTE on a fixed `(xi, msg, rnd)`, all 3 sets, both XOF modes (SHA3 + NGCC) and both sig formats (rANS + `-DSIG_RAW`); plus Python verify accepts own+C sig, C ref verify accepts, tampered sig rejected |

The deterministic-input C dumpers either seed a xorshift64 mirrored exactly in
Python (reduce/rans/sampler) or take a fixed `(xi, msg, rnd)` mirrored in
`xcheck_sign.py` (sign); the Python side recomputes every dumped value and
asserts equality.

### End-to-end sign byte-replay (`--sign`)

`xcheck_sign.py` is the capstone: it builds `sign_dump.c` against the real C
scheme and asserts the Python `keygen`/`sign` reproduce the C `pk`/`sk`/`sig`
byte-for-byte. **Verified byte-exact: all 3 sets x {SHA3, NGCC} x {rANS, RAW}
(12 configurations).** The hard parts -- the masking-Gaussian SampleY
(ApproxExp accept + mini-batch byte schedule), ExpandS keygen noise, the IRS
`reject_sample` (single bulk `tau*18` buffer, ascending-j, SamplerU/ApproxLog
decode), the mod-2q commitment lift, MakeHint/UseHint, and the rANS sigEncode
-- are all reproduced exactly.

## Realignment with the current C XOF schedule (2026-09-29)

The mirror had fallen out of sync: SHUTTLE commit `16dfdfc` (2026-06-27,
"Remove XOF refill counter: single-init samplers + N-way bulk-preset gauss")
replaced the per-lane **refill re-init** model (`nonce = tag||seed||LE16(lane)||LE16(refill)`,
a fresh `XOF.Init` per block) with **one init per lane + a chain of fixed-size
squeezes off the persisted ctx**, and re-recorded the KAT. `tools/pyref` was not
updated then, so `xcheck_sign.py` failed on every configuration (pk/sk/sig all
differed) from that commit until the realignment below.

`xof_ref.py` / `sign_ref.py` now mirror the current schedule:

| stream | tag | nonce | per-squeeze unit |
|---|---|---|---|
| ExpandA (`UniformStream`) | `0x02` | `tag‖seedA‖LE16(lane)` | `UNIFORM_DRAW` = `ceil(2·(EM·n·(1+ELL)/16)·BQ → granularity)` |
| ExpandS (`GaussStream`) | `0x03` | `tag‖seedsk‖LE16(lane)` | `GAUSS_BLOCK_S` = `NOISE_MINIBATCH_RAND_BYTES` |
| SampleY (`GaussStream`) | `0x08` | `tag‖seedY‖LE16(lane)` | first squeeze: sign bytes + 8 padding + 676; later squeezes: 676 (672-byte candidate body + 4 fold bytes) |
| SampleC (inline) | `0x07` | `tag‖seedC‖LE16(0)` | `SAMPLEC_DRAW` = `ceil(TAU·BN·2 → granularity)` |

`granularity` is `XOF_SQUEEZE_GRANULARITY_BYTES` (SHAKE128 rate 168 under
`SHA3_MODE`, the 32-word SM3 block 128 under `NGCC_MODE`). No refill counter
survives on either side. `python3 run_pyref.py --sign` and
`xcheck_sign.py --mode all [--ngcc] [--raw]` are byte-exact again across all
3 sets x {SHA3, NGCC} x {rANS, RAW}; the end-to-end check is wired into
`./run_tests.sh` (skippable with `SKIP_PYREF=1`).

## M4 empirical rANS validation

`m4_validate.py` (+ `m4_dump.c`) signs N real messages with the C rANS path,
parses the realized rANS com length and the Q0/Qs/h symbols, and checks the
`RANS_RESERVED_BYTES` reserve holds (no overflow) + the empirical laws match
the model PMFs (`tools/rans_model.py`).

## Run

    python3 run_pyref.py --selftest    # every module self-test
    python3 run_pyref.py --xcheck      # build+run the 3 C byte-exact xchecks
    python3 run_pyref.py --sign        # end-to-end keygen/sign/verify xcheck
    python3 run_pyref.py --m4 10000    # M4 empirical reserve check (N sigs)
    python3 run_pyref.py --all         # selftest + xcheck + sign

    # sign xcheck variants (driven directly):
    python3 xcheck_sign.py --mode all          # SHA3, rANS
    python3 xcheck_sign.py --mode all --ngcc   # NGCC (SM3 DRBG), rANS
    python3 xcheck_sign.py --mode 128 --raw    # -DSIG_RAW fixed-length path

C dumpers (`*_dump_*`, `*_oracle_*`) are build artifacts written next to the
sources; they are gitignored.
