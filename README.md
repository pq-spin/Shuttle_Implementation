# SHUTTLE

SHUTTLE is a lattice-based digital signature scheme: a Module-LWE Fiat-Shamir-with-aborts construction whose distinguishing feature is a *rejection-free inner masking loop* (the Iterated Rejection Sampler, IRS). Where a classic FSwA signer redraws the masking vector and restarts the whole signature on a rejected response, SHUTTLE walks the response toward an accepted lattice point one challenge-bit at a time, so the inner loop never aborts; only the outer norm gate and the entropy-coder support check can trigger a restart. The scheme is strongly unforgeable (SUF-CMA).

This repository ships three byte-exact implementations of SHUTTLE -- a pure-C99 scalar reference, an AVX2 build, and an AVX-512 build -- across three security levels, SHUTTLE-128, SHUTTLE-256, and SHUTTLE-512. Every level is available with either of two interchangeable symmetric (hash/XOF) backends: the SM3-based backend used as the default competition interface, and a SHAKE backend for apples-to-apples comparison against NIST lattice schemes. Within a fixed security level and symmetric backend, the reference, AVX2, and AVX-512 builds produce identical keys, signatures, and known-answer transcripts down to the byte.

## What it is

- Signature family: Module-LWE Fiat-Shamir-with-aborts, strongly unforgeable (SUF-CMA), with a rejection-free inner masking transition (IRS / a uniform-sampler `SamplerU` / a base-2 `ApproxLog` test) replacing the conventional outer-loop response rejection.
- Three security levels: SHUTTLE-128, SHUTTLE-256, SHUTTLE-512 (targeting roughly 128-, 256-, and 512-bit security). Each level is a separate build; there is no runtime level dispatch.
- Three implementations: `ref/` (portable scalar C99, also the reference oracle), `avx2/`, and `avx512/`. All three are byte-exact for a given level and symmetric backend.
- Two symmetric backends, selected at build time:
  - The default backend is built on an SM3 hash-DRBG and is the competition interface.
  - A SHAKE (Keccak) backend is selectable for direct comparison against NIST/SUPERCOP-style schemes.
  The two backends are genuinely distinct primitives and therefore define two distinct known-answer-test (KAT) sets; the reference and the two vectorized builds must agree byte-for-byte within each backend.
- Integer-only constant-time discipline: no floating point, no secret-dependent branches, no secret-dependent division or table-gather anywhere on the secret path. All `exp`/`log` evaluations needed by the samplers are fixed-point polynomial kernels with audited precision.

## Parameter sets

| Level | Ring degree $n$ | Modulus $q$ | NTT layout | Public key | Secret key | Signature (typical / bound) |
| --- | --- | --- | --- | --- | --- | --- |
| SHUTTLE-128 | 256 | 15361 | signed int16 | 1264 B | 2288 B | 1183 B / 1216 B |
| SHUTTLE-256 | 512 | 61441 | unsigned uint16 (valley) | 1952 B | 3680 B | 2417 B / 2432 B |
| SHUTTLE-512 | 1024 | 59393 | unsigned uint16 (valley) | 3648 B | 5056 B | 5001 B / 5056 B |

The module rank is fixed at $\ell = 3$ secret components across all levels; the error-vector component count and the challenge Hamming weight grow with the level. Public-key and secret-key sizes are exact and pinned by compile-time assertions. The signature is variable-length (it is entropy-coded); the "typical" column is the realized packed length for the deterministic test message, and the "bound" column is the fixed capacity returned by the interface (`sig_get_sn_len_bytes`). Every value in this table is reproduced verbatim by the build (see Reproducible constants).

## Directory structure

```
SHUTTLE/
  ref/         pure C99 scalar -- the reference implementation and the KAT oracle
  avx2/        AVX2 build; symlinks the shared scalar files from ref/, forks only vectorized files
  avx512/      AVX-512 build; same sharing model, forks the AVX-512 kernels
  tools/       reproducible constant generators, a Python reference model, and audit/bench helpers
  docs/        design notes (constant-time methodology, perf-review checklist)
  *.sh         the security/audit harness (run_tests.sh and the audit matrices)
  BUILD.md     build-system conventions and submission-folder mapping
```

`ref/` is the single source of truth. `avx2/` and `avx512/` relative-symlink every file they do not need to change (the per-level parameter header, the API headers, all scalar math that the vectorized path reuses) and *fork* only the files that carry vector code -- per-backend configuration, the polynomial-vector layer, the samplers, the IRS, rounding, the top-level sign driver, plus the SIMD XOF/NTT kernels. The fork carries a backend-specific symbol-namespace tail (`_ref` / `_avx2` / `_avx512`) so that all three levels times all three backends can co-link in one process without symbol clash.

Key modules (each lives under `ref/` and is reused or forked by the vectorized backends):

- XOF / symmetric layer (`xof.h`, `symmetric.{c,h}`, `drng.{c,h}`, `fips202.{c,h}`): one unified four-primitive XOF interface that resolves at build time to either the SM3 hash-DRBG or SHAKE. Every randomness draw in keygen/sign/verify flows through it.
- NTT (`poly_ntt.{c,h}`, `ntt/<config>/`): per-modulus number-theoretic transform; one signed valley layout for SHUTTLE-128 and two unsigned valley layouts for the larger levels, hidden behind a uniform shim.
- Base sampler (`sampler.{c,h}`): constant-time reverse-CDT discrete-Gaussian sampler with a 96-bit (three 32-bit limb) cumulative-distribution comparison.
- Masking / accept sampler (`sampler_u.{c,h}`, `approx_exp.{c,h}`, `approx_log.{c,h}`): the wide masking-vector sampler and the integer-only fixed-point `exp` / base-2 `log` kernels that drive the accept tests.
- IRS (`irs.{c,h}`): the rejection-free inner masking transition that maps the masking sample to the signed response, running exactly $\tau$ (the challenge Hamming weight) transitions per signature.
- rANS codec (`rans.{c,h}`): a static, byte-renormalized range-asymmetric-numeral-system entropy coder that compresses the signature triple into the on-wire packet; it operates only on public post-signing data.
- Packing / rounding (`packing.{c,h}`, `rounding.{c,h}`, `poly.{c,h}`, `polyvec.{c,h}`): serialization, high/low-bit decomposition, and polynomial-vector arithmetic.
- Sign driver (`sign.{c,h}`): top-level KeyGen / Sign / Verify control flow; it owns no subroutine math, only the ordering and the derived-matrix builds.
- Interfaces (`SIG_AlgorithmInstance.{c,h}` and `api.h`): the competition `sig_*` interface adapter, and an in-tree NIST/SUPERCOP-style API used by the test drivers.

## Build and test

Builds are driven by `make` in each backend directory. The security level is a compile-time choice injected per binary via `SHUTTLE_MODE` (128, 256, or 512); the `MODES` make-variable selects which levels to build. There is no runtime mode dispatch -- each binary is exactly one parameter set.

```sh
# Reference backend: build and run every test for every level
make -C ref check

# Build/test a single level
make -C ref check MODES=256

# AVX2 and AVX-512 backends (also assert byte-equality against the reference)
make -C avx2   check
make -C avx512 check

# Reference warning gate: the reference build must be warning-clean
make -C ref check-warn
```

`make -C ref check` builds the full per-level test suite (parameters, XOF, reduction, NTT, packing, samplers, IRS, rounding, rANS, end-to-end sign, and the KAT) and asserts a zero exit for each. The AVX2/AVX-512 `check` targets additionally verify that their output is byte-identical to the reference.

The competition interface is the four `sig_*` functions declared in `ref/SIG_AlgorithmInstance.h`:

```c
int sig_keygen(unsigned char *pk, unsigned long long *pk_len,
               unsigned char *sk, unsigned long long *sk_len);
int sig_sign  (unsigned char *sk, unsigned long long sk_len,
               unsigned char *m,  unsigned long long m_len,
               unsigned char *sn, unsigned long long *sn_len);
int sig_verify(unsigned char *pk, unsigned long long pk_len,
               unsigned char *sn, unsigned long long sn_len,
               unsigned char *m,  unsigned long long m_len);
```

`sig_keygen` / `sig_sign` return 0 on success and a negative error code otherwise; `sig_verify` returns 0 for a valid signature and -1 for an invalid one. The companion `sig_get_pk_len_bytes` / `sig_get_sk_len_bytes` / `sig_get_sn_len_bytes` report the claimed byte lengths. An in-tree NIST-style API (`crypto_sign_keypair` / `crypto_sign_signature` / `crypto_sign_verify`, in `api.h`) is also provided for the test drivers. Each backend builds its per-level test binaries under `<backend>/out/<test>_<level>` (for example `avx2/out/test_kat_256`).

### Submission builds and exact compile flags

The three backends map onto the three submission categories, each with a fixed compiler flag string.

- Reference (`ref/`) -- pure ISO C99, no assembly, intrinsics, or extensions; must be warning-clean:

  ```sh
  gcc -std=c99 -Wpedantic -Wall -Wextra -O2
  ```

- Optimized (`avx2/`) -- a pure-AVX2 path; `-mno-avx512f` transitively disables every AVX-512 subset while keeping AVX2/BMI2/POPCNT, and is enforced by a dedicated objdump gate:

  ```sh
  gcc -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
      -std=c99 -Wpedantic -Wall -Wextra -mbmi2 -mpopcnt -mno-avx512f
  ```

- Additional (`avx512/`) -- the Optimized flags minus `-mno-avx512f`, plus the AVX-512 subsets:

  ```sh
  gcc -O3 -march=x86-64 -mavx2 -mtune=native -flto -fomit-frame-pointer \
      -std=c99 -Wpedantic -Wall -Wextra -mbmi2 -mpopcnt \
      -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vbmi2
  ```

The AVX-512 build steps outside the fixed Optimized flag string (it adds the `-mavx512*` subsets, and the SIMD XOF requires VBMI2), so it ships as the Additional category. The pedantic warnings on the two vectorized builds (intrinsics and inline assembly are not ISO C99) are tolerated because the flag set is fixed; only the reference build is held to the strict warning-clean bar, enforced by `make -C ref check-warn` (which adds `-Werror`).

## Switching the symmetric backend

The symmetric backend is a second, orthogonal build-time axis controlled by the `MODE` make-variable. The default (no extra flag) is the SM3 hash-DRBG competition interface; `make MODE=SHA3 ...` injects the SHAKE backend.

```sh
# Default (SM3 hash-DRBG) backend
make -C ref check
make -C ref check-kat

# SHAKE backend
make -C ref MODE=SHA3 check
make -C ref MODE=SHA3 check-kat
```

The two backends are distinct primitives and therefore define two distinct KAT sets. Each `check-kat` invocation replays the byte protocol, hashes the public-key / secret-key / signature transcript, and asserts the result equals the recorded value (and that the signature verifies and that a tampered signature is rejected). The recorded hashes are:

| Level | Default (SM3) backend | SHAKE backend |
| --- | --- | --- |
| SHUTTLE-128 | 5525731303976652954 | 11439871523140599355 |
| SHUTTLE-256 | 4684222326669620474 | 8372293911548186006 |
| SHUTTLE-512 | 8059965594724964533 | 12332646238986233852 |

These are the production (entropy-coded signature path) hashes, verified to reproduce across the reference, AVX2, and AVX-512 backends for both symmetric backends. **Keep this table in sync with the `KAT_<level>_<MODE>` pins in `ref/Makefile` (also mirrored in `avx2/Makefile` and `avx512/Makefile`): the pins are authoritative, and every output-changing commit must re-record both.**

## Reproducible constants

Every runtime constant in the scheme is derivable from the parameter set by an in-repository generator -- there are no magic numbers. Each generated value lives in a delimited auto-generated region inside a committed header, emitted by a Python generator under `tools/` together with an audit log.

```sh
# Regenerate every generated table from tools/*.py
make -C ref tables

# Drift gate: re-run every generator and prove the committed bytes are unchanged
make -C ref check-consts
```

`make tables` regenerates the derived parameter and bound constants, the NTT roots and constant tables, the sampler distribution tables, the fixed-point exp/log polynomial kernels, the IRS test constant, the rounding constants, and the rANS frequency/reciprocal tables. `make check-consts` re-runs each generator into a scratch copy and byte-compares against the committed header, failing on any drift; it also re-runs the quad-precision verifiers that prove the exp and log kernels meet their precision targets. This makes the entire constant surface auditable: a reviewer can regenerate everything from scratch and confirm bit-for-bit identity with what ships.

## Security audit

The single entry point is the gate-of-gates:

```sh
./run_tests.sh
```

It runs, fail-fast, the full functional suite, the recorded-KAT lock, the reproducible-constants drift gate, cross-backend byte-equality, and the audit matrices below. A failing gate is fatal; an audit target not present in a given checkout is a loud skip rather than a silent pass.

The audit harness has two defense families.

- Variable-latency / secret-division defense (the "KyberSlash" class): source-level constant-time is not sufficient, because a compiler can re-emit a hardware divide for a divide-by-constant at low optimization levels. The mandatory static machine-code scan descends to disassembly:

  ```sh
  ./ct_scan_matrix.sh        # -> tools/ct_scan.py
  ```

  It compiles every secret-handling object across the full matrix of backend x level x compiler (gcc and clang) x optimization level (`-O3` and `-Os`) x symmetric backend, disassembles each, and flags any forbidden mnemonic -- division, gather/scatter, square root, float conversion -- unless it is explicitly allowlisted as operating on public data or a public-length count. Every allowlist entry cites a section of `SECRET_PUBLIC_AUDIT.md`. This is complemented by a statistical timing-leakage test (the dudect methodology, `./run_dudect_all.sh`) and an opt-in dynamic taint check (a patched-Valgrind run, enabled with `TIMECOP=1 ./run_tests.sh`).

- Correctness/leakage bugs that pass functional tests (the class of divergences that are functionally clean but wrong on some input): defended by the independent Python reference model (`tools/pyref/`), whose end-to-end `pk`/`sk`/`sig` byte-exactness against the C reference is now part of `./run_tests.sh` (`python3 tools/pyref/run_pyref.py --sign`; skip it in a quick loop with `SKIP_PYREF=1`), the deterministic recorded KAT, byte-for-byte cross-backend equality, plus two matrices:

  ```sh
  ./integration_audit_matrix.sh   # cross-backend differential fuzz
  ./security_audit_matrix.sh      # fault injection + negative-parser corpus
  ```

  The differential fuzz drives many random cases through each backend and asserts identical transcripts. The security matrix asserts that every tampered key or faulted input is handled deterministically (no crash, no accept of a corrupted signature, no cross-message forge) and that every malformed signature -- wrong length, bad challenge seed, entropy-decode failure, out-of-range hint -- is a deterministic public reject.

The governing policy is: no floating point, no secret-dependent branch, and no secret-dependent division anywhere on the secret path. The secret/public classification baseline -- which bytes are secret, which are public, which are public-length, and which are deliberately declassified -- is documented in `SECRET_PUBLIC_AUDIT.md`, and every constant-time-scanner exemption cites it. Memory-footprint helpers (`tools/static_mem.sh`, `tools/peak_mem.sh`) report the deployable library's static and peak-runtime memory.

## Performance

The table below is **preliminary (i7-class, WSL2, unpinned) -- to be re-measured on a pinned, Turbo/HT-disabled native machine**. Numbers are median rdtsc cycles per operation (keygen and sign reported as the 50th percentile of a wide latency distribution; verify is rejection-free and reported as a straight median), plus sign throughput in operations per second measured over a wall-clock loop. Measured on an Intel Core i7-11700K (Rocket Lake, nominal 3.6 GHz) under WSL2 with gcc, across all three backends and both symmetric backends. Because the host is unpinned with Turbo and hyper-threading active, the per-sample variance is large (coefficient of variation around 80% on the keygen/sign tails); treat these as representative magnitudes, not final figures.

To reproduce (the per-run count is reduced from the default for a fast representative sweep):

```sh
make -C ref    speed MODES="128 256 512" SPEED_EXTRA="-DBENCH_SIGN_RUNS=2000 -DNGCC_ITERS=200"
make -C avx2   speed MODES="128 256 512" SPEED_EXTRA="-DBENCH_SIGN_RUNS=2000 -DNGCC_ITERS=200"
make -C avx512 speed MODES="128 256 512" SPEED_EXTRA="-DBENCH_SIGN_RUNS=2000 -DNGCC_ITERS=200"
# add MODE=SHA3 to any of the above for the SHAKE backend
```

### Default (SM3 hash-DRBG) backend

| Level | Backend | KeyGen (cyc) | Sign (cyc) | Verify (cyc) | Sign (ops/s) |
| --- | --- | ---: | ---: | ---: | ---: |
| SHUTTLE-128 | ref | 11227370 | 18631981 | 2681886 | 154 |
| SHUTTLE-128 | avx2 | 6967228 | 5380916 | 1073076 | 401 |
| SHUTTLE-128 | avx512 | 6334656 | 4148186 | 798488 | 444 |
| SHUTTLE-256 | ref | 9812986 | 8117036 | 2637162 | 432 |
| SHUTTLE-256 | avx2 | 7102542 | 2498508 | 1053530 | 1361 |
| SHUTTLE-256 | avx512 | 6609042 | 1718144 | 951480 | 1733 |
| SHUTTLE-512 | ref | 14970702 | 15224488 | 3145860 | 226 |
| SHUTTLE-512 | avx2 | 14294114 | 4070828 | 1375796 | 774 |
| SHUTTLE-512 | avx512 | 13709016 | 3311996 | 1183974 | 988 |

### SHAKE backend

| Level | Backend | KeyGen (cyc) | Sign (cyc) | Verify (cyc) | Sign (ops/s) |
| --- | --- | ---: | ---: | ---: | ---: |
| SHUTTLE-128 | ref | 3466490 | 8373042 | 900218 | 288 |
| SHUTTLE-128 | avx2 | 2342680 | 3128644 | 477866 | 866 |
| SHUTTLE-128 | avx512 | 2298302 | 2530480 | 321722 | 964 |
| SHUTTLE-256 | ref | 3495142 | 5991986 | 1138986 | 569 |
| SHUTTLE-256 | avx2 | 2211610 | 1383808 | 471884 | 2300 |
| SHUTTLE-256 | avx512 | 2319850 | 1065024 | 441670 | 2057 |
| SHUTTLE-512 | ref | 7067426 | 10349742 | 1525006 | 315 |
| SHUTTLE-512 | avx2 | 4386339 | 2865668 | 862982 | 1041 |
| SHUTTLE-512 | avx512 | 4816750 | 2387496 | 771266 | 1357 |

The dominant cost driver is the symmetric primitive (the XOF / hash), not the lattice arithmetic. This is visible directly in the data: switching from the SM3 hash-DRBG backend to SHAKE -- while keeping every lattice operation identical -- cuts keygen by a factor of roughly two to three and roughly halves sign and verify, because the SM3 DRBG emits only 32 bytes per compression and the scheme is hash-bound. It also explains why the AVX2-to-AVX-512 step is modest relative to the reference-to-AVX2 step: once the vectorized N-way hash absorbs most of the cost, the remaining lattice arithmetic is a smaller slice. KeyGen on SHUTTLE-512 stays expensive on all backends because of its norm-window rejection (the key is redrawn until its norm lands in a target band).

## License and provenance

SHUTTLE is developed as a submission to the Next-generation Commercial Cryptographic Algorithms (NGCC) program of the Institute of Commercial Cryptography Standards (ICCS); the `sig_*` interface contract and its accompanying notice originate from that program. The SHAKE backend uses a vendored public-domain Keccak (FIPS 202) implementation. The repository upstream is `https://github.com/Ji-Peng/SHUTTLE`. Refer to the repository for the authoritative license terms.
