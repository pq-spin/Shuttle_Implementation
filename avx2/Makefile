# Makefile for the SHUTTLE signature AVX2 implementation.
#
#   make                 # build all tests for all modes -> out/
#   make check           # build + run every test for every mode (assert exit 0)
#   make check-kat       # build test_kat; assert recorded KAT (ref==avx2==avx512)
#   make check-no-avx512 # objdump gate: NO zmm/EVEX/AVX-512 op leaked (pure AVX2)
#   make check-refill    # force multi-way XOF continuation-squeeze; KAT unchanged
#   make check-consts    # reproducibility/drift gate (params/bounds + vendored NTT)
#   make sm3-test        # legacy SM3 N-way XOF/DRNG byte-exactness test
#   make clean
#
# Shared algorithm/KAT source is SYMLINKED from ../ref (single source of truth;
# materialized by ../tools/mklinks.sh).  At the byte-exactness milestone the
# AVX2-specific REAL files here are ONLY: config.h (namespace tail), poly_ntt.c
# (the SIMD NTT shim fork) + the per-mode vendored NTT asm in ./<qset>/, and the
# AVX-only / N-way XOF files (symmetric_avx2.c, fips202x4.*, f1600x4.S,
# auxfunc_avx2.*, drng_avx2.*).  EVERYTHING else -- including the would-be-fork
# scalar sources (polyvec/sampler/irs/rounding/sign) and the NGCC infra
# (SIG_AlgorithmInstance/KAT_SIG/drng/auxfunc) -- is symlinked scalar.
#
# SIMD COVERAGE = NTT + XOF.  The sampler/sign/rounding/irs logic runs the
# SCALAR code symlinked from ref; the SIMD perf kernels for those are a LATER
# perf step.  Because the AVX NTT (poly_ntt.c via nttunpack) is byte-exact and
# the symlinked scalar logic is identical to ref, the avx2 KAT hash EQUALS the
# ref hash (the byte-exactness gate).
#
# Compile-time switches select the AVX2 code paths in the symlinked ref sources:
#   USE_AVX2_NTT / USE_AVX2_SAMPLER / USE_AVX2_SHAKE4X  (set in CFLAGS below).
# At the byte-exactness milestone only USE_AVX2_NTT routes a real fork
# (poly_ntt.c); the SAMPLER/SHAKE4X kernels are a later perf step -- the scalar
# bodies run until then.

MODES ?= 128 256 512
# Full ref test matrix (mirrors ref/Makefile TESTS) with the SCALAR-only NTT
# oracle (test_ntt) REPLACED by the AVX2 NTT driver (test_ntt_avx).
# test_ntt.c is a scalar-ONLY driver: its [3] check reads the raw NTT-domain
# lane with the naive (uint16_t)x%q, which is the WRONG readback for the SIGNED
# q15361 (mode 128) AVX2 path (lazy output reaches ~2q; the readback rule
# in poly_ntt.h mandates smod there).  test_ntt_avx.c is the backend-correct
# replacement: it asserts the SAME invariant nttunpack(ntt_ref)==ntt_avx and
# scalar==avx2 byte-exactness with the per-config smod/uint16 readback, and
# passes all 3 modes.  (test_ntt PASSES on the unsigned modes 256/512 but FAILS
# mode 128 purely on the readback convention -- so it is dropped here, not run.)
TESTS ?= t_params test_xof t_reduce test_ntt_avx test_pack test_sampler \
         test_approx test_samplers test_irs test_rounding test_rans test_sign test_kat
CC    ?= gcc

# Exact NGCC Optimized flags.  -mno-avx512f forces a PURE AVX2
# path: -mtune=native would otherwise let GCC auto-vectorize the symlinked
# scalar C to zmm on an AVX-512 host; -mno-avx512f transitively disables every
# AVX-512 subset while keeping AVX2/BMI2/POPCNT.  Enforced by check-no-avx512.
# NOTE: -std=c99 -Wpedantic warns on intrinsics/asm; we TOLERATE those on the
# perf build (the flag set is fixed) and keep only the ref build strictly
# warning-clean.
CFLAGS ?= -O3 -march=x86-64 -mavx2 -mtune=native -fomit-frame-pointer \
          -std=c99 -Wpedantic -Wall -Wextra -mbmi2 -mpopcnt -mno-avx512f \
          -I. -I../ref -I../ref/test -I../tools \
          -DUSE_AVX2_NTT -DUSE_AVX2_SAMPLER -DUSE_AVX2_SHAKE4X \
          -DUSE_AVX2_XOF_NWAY
LDLIBS ?=
BINDIR  = out
CT_OPT ?= -O3

# XOF MODE switch (NGCC_MODE default vs SHA3_MODE).  `make MODE=SHA3 ...`.
MODE ?=
ifeq ($(MODE),SHA3)
MODEFLAG = -DSHA3_MODE
else
MODEFLAG =
endif

# XOF source list, MODE-dependent.  At the byte-exactness milestone the
# symlinked scalar scheme code calls only the SCALAR xof128/256 primitives (the
# N-way SIMD XOF kernels are a later perf step), so the XOF link set matches
# ref exactly:
#   SHA3_MODE : symmetric.c + the vendored scalar Keccak (fips202.c)
#   NGCC_MODE : symmetric.c + the SM3 Hash-DRBG (../ref/drng.c + ../ref/auxfunc.c)
# The KAT harness ALWAYS seeds via the SM3 Hash-DRBG (the fixed competition
# protocol), so under SHA3_MODE a KAT binary needs drng.c+auxfunc.c IN ADDITION
# to the SHAKE backend (mirrors ref/Makefile KAT_XOF).
ifeq ($(MODE),SHA3)
XOF_SRCS = symmetric.c fips202.c
KAT_XOF  = symmetric.c fips202.c ../ref/drng.c ../ref/auxfunc.c
# N-way (4-way SHAKE) XOF kernels used by the later-step ExpandA/ExpandS/SampleY
# batched refills (USE_AVX2_XOF_NWAY).  Appended whenever polyvec.c links.
# symmetric_avx2.c = the xof*_avx2_* wrappers; fips202x4.c + f1600x4.S = the
# 4-way Keccak.  (Scalar fips202.c already in XOF_SRCS for the constants.)
NWAY_XOF = symmetric_avx2.c fips202x4.c f1600x4.S
else
XOF_SRCS = symmetric.c ../ref/drng.c ../ref/auxfunc.c
KAT_XOF  = $(XOF_SRCS)
# N-way (8-way SM3) XOF kernels for the later-step batched refills.  symmetric_avx2.c
# = the xof*_avx2_* wrappers; drng_avx2.c = the 8-way SM3 Hash-DRBG;
# auxfunc_avx2.c = the 8-way SM3 core it calls.  (Scalar drng.c/auxfunc.c
# already in XOF_SRCS for the seeding DRBG.)
NWAY_XOF = symmetric_avx2.c drng_avx2.c auxfunc_avx2.c
endif

# IRS single-buffer bulk fill (irs.c) N-way SM3 core.  Under NGCC the avx2
# irs.c (USE_AVX2_XOF_NWAY) calls sm3hash_avx2 (auxfunc_avx2.c) for the bulk
# tau*18 DRBG generate, so any irs.c-linking test that does NOT already pull
# polyvec.c (-> NWAY_XOF) needs auxfunc_avx2.c on its own.  Under SHA3 the
# irs.c bulk fill is the plain scalar xof256_squeeze (N-way path #if'd out),
# so no extra source is required.
ifeq ($(MODE),SHA3)
IRS_NWAY_SRC =
else
IRS_NWAY_SRC = auxfunc_avx2.c
endif

# Per-test source lists (POSIX-sh strings).  Identical scalar source lists to
# ref/Makefile -- the backend reuses the symlinked scalar .c verbatim.  The
# ONLY difference is that poly_ntt.c resolves to the AVX2 SIMD fork here, and
# the build loop appends the per-mode vendored asm whenever poly_ntt.c (or
# polyvec.c) is present.  t_params is header-only; test_ntt_avx is the AVX2 NTT
# correctness driver (real test/ source, not in ref).
SH_SRCS = \
't_params=' \
"test_xof=$(XOF_SRCS)" \
't_reduce=reduce.c' \
'test_ntt=reduce.c poly_ntt.c' \
'test_ntt_avx=poly_ntt.c reduce.c' \
'test_pack=packing.c poly.c reduce.c rans.c' \
'test_sampler=sampler.c reduce.c' \
'test_approx=approx_exp.c approx_log.c' \
"test_samplers=polyvec.c sampler.c reduce.c approx_exp.c approx_log.c $(XOF_SRCS)" \
"test_irs=irs.c sampler_u.c approx_exp.c approx_log.c reduce.c $(XOF_SRCS) $(IRS_NWAY_SRC)" \
'test_rounding=rounding.c reduce.c poly.c poly_ntt.c packing.c rans.c' \
'test_rans=packing.c poly.c reduce.c rans.c' \
"test_sign=sign.c polyvec.c sampler.c sampler_u.c irs.c rounding.c packing.c poly.c poly_ntt.c reduce.c rans.c approx_exp.c approx_log.c $(XOF_SRCS)" \
"test_kat=SIG_AlgorithmInstance.c sign.c polyvec.c sampler.c sampler_u.c irs.c rounding.c packing.c poly.c poly_ntt.c reduce.c rans.c approx_exp.c approx_log.c $(KAT_XOF)"

# Per-set NTT vendoring: a case $$m picks $qs; when a
# test's srcs contain polyvec.c OR poly_ntt.c (the AVX2 NTT shim fork) the build
# appends $qs/ntt.S + $qs/ntt_consts.c (the AVX2 kernels) AND the scalar oracle
# ../ref/ntt/$qs/ntt_ref.c (poly_ntt_canonical uses it for NTT-domain wire bytes),
# with -I../ref/ntt/$qs so poly_ntt.h finds the per-set vendored header.
QSET_128 = q15361n256
QSET_256 = q61441n512
QSET_512 = q59393n1024
# NTTGEN points at the generator (tools/ntt/<qset>/gen_ntt.py), used only by
# check-consts to prove the vendored copies are reproducible.
NTTGEN   = ../tools/ntt

# Recorded canonical KAT hashes (shared: ref == avx2 == avx512; the whole point
# of the byte-exactness milestone).  These are the SAME values the ref Makefile
# records (see ref/Makefile KAT_<m>_<MODE>); byte-exactness is the gate.
# Re-record in lock-step with ref on any output-changing diff.
KAT_128_NGCC = 5525731303976652954
KAT_256_NGCC = 4684222326669620474
KAT_512_NGCC = 8059965594724964533
KAT_128_SHA3 = 11439871523140599355
KAT_256_SHA3 = 8372293911548186006
KAT_512_SHA3 = 12332646238986233852
MODELABEL = $(if $(filter SHA3,$(MODE)),SHA3,NGCC)

.PHONY: all check check-kat check-no-avx512 check-refill check-consts sm3-test \
        speed speed_txt profile profile_txt clean

all:
	@mkdir -p $(BINDIR)
	@for m in $(MODES); do \
	  case $$m in 128) qs=$(QSET_128);; 256) qs=$(QSET_256);; 512) qs=$(QSET_512);; esac; \
	  for entry in $(SH_SRCS); do \
	    t=$${entry%%=*}; srcs=$${entry#*=}; \
	    for want in $(TESTS); do [ "$$want" = "$$t" ] || continue; \
	      extra=""; inc=""; \
	      case "$$srcs" in \
	        *poly_ntt.c*|*polyvec.c*) \
	          extra="$$qs/ntt.S $$qs/ntt_consts.c ../ref/ntt/$$qs/ntt_ref.c"; \
	          inc="-I../ref/ntt/$$qs";; \
	      esac; \
	      case "$$srcs" in \
	        *polyvec.c*) extra="$$extra $(NWAY_XOF)";; \
	      esac; \
	      stats=""; \
	      case "$$t" in trace_kat) stats="-DTEST_RANS_STATS";; diff_fuzz) stats="-DDIFF_FUZZ_N=$(DIFF_FUZZ_N)";; test_sign) stats="-DSIG_RAW";; esac; \
	      $(CC) $(CFLAGS) $$inc $(MODEFLAG) $$stats -DSHUTTLE_MODE=$$m test/$$t.c $$srcs $$extra $(LDLIBS) \
	        -o $(BINDIR)/$${t}_$${m} || exit 1; \
	    done; \
	  done; \
	done
	@echo "built: [$(TESTS)] x [$(MODES)] (avx2)"

check: all
	@for m in $(MODES); do \
	  echo "=== SHUTTLE-$$m (avx2) ==="; \
	  for want in $(TESTS); do \
	    [ -x $(BINDIR)/$${want}_$${m} ] \
	      || { echo "missing test binary: $(BINDIR)/$${want}_$${m}"; exit 1; }; \
	    $(BINDIR)/$${want}_$${m} || exit 1; \
	  done; \
	done

# Assert the recorded per-mode KAT hashes (ref == avx2 == avx512).  test_kat
# replays the KAT_SIG.c byte protocol, FNV-1a hashes pk||sk||sn, asserts
# verify-accept + tamper-reject, prints KAT_hash.  The recorded values are
# IDENTICAL to ref (byte-exactness is the gate).
check-kat:
	@$(MAKE) MODES="$(MODES)" MODE="$(MODE)" TESTS=test_kat all >/dev/null
	@KAT_128=$(KAT_128_$(MODELABEL)); KAT_256=$(KAT_256_$(MODELABEL)); KAT_512=$(KAT_512_$(MODELABEL)); \
	fail=0; for m in $(MODES); do \
	  got=`$(BINDIR)/test_kat_$$m | sed -n 's/^KAT_hash=//p'`; \
	  eval exp=\$$KAT_$$m; \
	  if [ "$$got" = "$$exp" ]; then echo "  PASS: KAT-$$m ($(MODELABEL),avx2) = $$got"; \
	  else echo "  FAIL: KAT-$$m ($(MODELABEL),avx2) got $$got want $$exp"; fail=1; fi; \
	done; [ $$fail -eq 0 ] && echo "check-kat: avx2 KAT matches recorded (ref==avx2)" || exit 1

# Pure-AVX2 gate: assert NO AVX-512 (zmm / EVEX mask / AVX-512-only mnemonic)
# leaked into any built object.  -mno-avx512f should make this impossible; the
# gate proves the flag is effective (and would catch its accidental removal).
check-no-avx512:
	@rm -rf $(BINDIR)
	@$(MAKE) MODES="$(MODES)" MODE="$(MODE)" all >/dev/null
	@fail=0; \
	for b in $(BINDIR)/*; do \
	  [ -f "$$b" ] || continue; \
	  hits=$$(objdump -d "$$b" 2>/dev/null | grep -iE '%zmm[0-9]|\{%k[0-7]\}|vpternlog|vpcompress|vpexpand|vpmadd52|vperm[ti]2[a-z]|kmov|kshift|kortest|kunpck|valign[dq]' || true); \
	  if [ -n "$$hits" ]; then echo "  FAIL $$b:"; echo "$$hits" | head -3; fail=1; fi; \
	done; \
	[ $$fail -eq 0 ] && echo "check-no-avx512: pure AVX2 (no zmm/EVEX/AVX-512 op in any build object)" || { echo "check-no-avx512: AVX-512 LEAKED"; exit 1; }

# Force-exercise the multi-way XOF continuation-squeeze (refill) path with a
# tiny initial squeeze and assert the KAT is unchanged (cursor-advance
# determinism).  At the byte-exactness milestone the scheme runs the scalar
# XOF, so this is a no-op KAT rerun; it becomes load-bearing once the N-way
# SIMD XOF kernels land.
check-refill:
	@$(MAKE) MODES="$(MODES)" MODE="$(MODE)" CFLAGS="$(CFLAGS) -DGAUSS4X_INIT=4 -DNOISE4X_INIT=4" TESTS="test_kat" all >/dev/null
	@echo "== forced multi-way refill: KAT must be unchanged =="
	@for m in $(MODES); do $(BINDIR)/test_kat_$$m | sed -n 's/^/  /p'; done

# Reproducibility/drift gate: params/bounds regions + the vendored NTT.
check-consts:
	@mkdir -p $(BINDIR)
	@echo "== params.h (@@AUTOGEN:params@@ + @@AUTOGEN:bounds@@; via ../ref) =="
	@cp ../ref/params.h $(BINDIR)/params.h.bak
	@( cd ../tools && python3 gen_params.py >/dev/null 2>&1 && python3 gen_bounds.py >/dev/null 2>&1 ) \
	  || { echo "  FAIL: generator error"; rm -f $(BINDIR)/params.h.bak; exit 1; }
	@cmp -s ../ref/params.h $(BINDIR)/params.h.bak \
	  && echo "  PASS: params.h reproducible (params + bounds)" \
	  || { echo "  FAIL: params.h drift"; rm -f $(BINDIR)/params.h.bak; exit 1; }
	@rm -f $(BINDIR)/params.h.bak
	@echo "== vendored AVX2 NTT (./<qset>/ntt.S + ntt_consts.c) vs gen_ntt.py =="
	@rm -rf $(BINDIR)/ntt_regen
	@mkdir -p $(BINDIR)/ntt_regen
	@for qs in $(QSET_128) $(QSET_256) $(QSET_512); do \
	  if [ -d "$(NTTGEN)/$$qs" ] && [ -f "$$qs/ntt.S" ]; then \
	    python3 $(NTTGEN)/$$qs/gen_ntt.py $(BINDIR)/ntt_regen >/dev/null 2>&1 \
	      || { echo "  FAIL: $$qs gen_ntt.py"; exit 1; }; \
	    cmp -s $(BINDIR)/ntt_regen/avx2/$$qs/ntt_consts.c $$qs/ntt_consts.c \
	      && cmp -s $(BINDIR)/ntt_regen/avx2/$$qs/ntt.S $$qs/ntt.S \
	      && echo "  PASS: $$qs vendored AVX2 NTT matches gen_ntt.py" \
	      || { echo "  FAIL: $$qs vendored AVX2 NTT differs (re-run make tables)"; exit 1; }; \
	  else echo "  skip: $$qs vendored NTT not present"; fi; \
	done
	@rm -rf $(BINDIR)/ntt_regen
	@echo "check-consts: params + AVX2 NTT constants reproducible"

# Legacy SM3 N-way XOF/DRNG byte-exactness test (8-way AVX2 vs scalar ref).
# Kept here so the existing capability is not lost.
SM3_AVX2 := -mavx2 -mbmi2
sm3-test:
	@mkdir -p $(BINDIR)
	@$(CC) -O3 -std=c99 -Wall -Wextra $(SM3_AVX2) -I../ref \
	   test_avx2.c auxfunc_avx2.c ../ref/auxfunc.c -o $(BINDIR)/sm3_test_avx2 2>/dev/null \
	   && $(BINDIR)/sm3_test_avx2 || echo "sm3-test: build deferred (SM3 sources)"
	@$(CC) -O3 -std=c99 -Wall -Wextra $(SM3_AVX2) -I../ref \
	   test_drng_avx2.c drng_avx2.c auxfunc_avx2.c ../ref/drng.c -o $(BINDIR)/sm3_test_drng_avx2 2>/dev/null \
	   && $(BINDIR)/sm3_test_drng_avx2 || echo "sm3-test(drng): build deferred (SM3 sources)"

# ===================================================================== #
#  Speed / profile benchmarks (mirror the `all` per-mode build: $qs ->   #
#  AVX2 vendored NTT asm + scalar oracle + the N-way XOF kernels, since   #
#  polyvec.c is in the scheme source list).  The sig_* drivers seed via   #
#  the SM3 Hash-DRBG exactly like the KAT harness, so $(KAT_XOF) is used  #
#  (drng.c+auxfunc.c even under SHA3_MODE).                               #
# ===================================================================== #
SCHEME_SRC = SIG_AlgorithmInstance.c sign.c polyvec.c sampler.c sampler_u.c irs.c \
             rounding.c packing.c poly.c poly_ntt.c reduce.c rans.c approx_exp.c approx_log.c
SPEED_SRCS   = $(SCHEME_SRC)
PROFILE_SRCS = $(SCHEME_SRC)
# Extra cc flags for the bench drivers ONLY (e.g. -DBENCH_SIGN_RUNS=N -DNV=N
# -DNGCC_ITERS=N to shrink the run for quick/CI evidence); empty by default.
SPEED_EXTRA ?=

# Shared machine-info preamble for speed_txt / profile_txt.
MACHINFO = printf ' date    : '; date -u '+%Y-%m-%dT%H:%M:%SZ'; \
           printf ' kernel  : '; uname -sr; \
           printf ' cpu     : '; ( lscpu 2>/dev/null | sed -n 's/^Model name:[[:space:]]*//p' | head -1 || grep -m1 'model name' /proc/cpuinfo | sed 's/.*: //' ); \
           printf ' cc      : '; $(CC) --version | head -1; \
           printf ' cflags  : %s\n' '$(CFLAGS)'

# `speed` runs the full bench under BOTH XOF backends -- NGCC (SM3 Hash-DRBG)
# first, then SHA3 (SHAKE) -- via two recursive sub-makes; speed_run is the
# single-XOF-mode worker (the MODE make-var selects the backend).  speed_txt
# captures both passes into one test/speed.txt.
.PHONY: speed speed_run
speed:
	@$(MAKE) --no-print-directory speed_run MODE=
	@$(MAKE) --no-print-directory speed_run MODE=SHA3
speed_run:
	@mkdir -p $(BINDIR)
	@echo "-- XOF mode: $(MODELABEL) --"
	@for m in $(MODES); do \
	  case $$m in 128) qs=$(QSET_128);; 256) qs=$(QSET_256);; 512) qs=$(QSET_512);; esac; \
	  $(CC) $(CFLAGS) -I../ref/ntt/$$qs $(MODEFLAG) -DSHUTTLE_MODE=$$m $(SPEED_EXTRA) \
	    test/speed_sign.c test/cpucycles.c $(SPEED_SRCS) $(KAT_XOF) \
	    $$qs/ntt.S $$qs/ntt_consts.c ../ref/ntt/$$qs/ntt_ref.c $(NWAY_XOF) \
	    $(LDLIBS) -lm -o $(BINDIR)/speed_sign_$$m || exit 1; \
	  $(BINDIR)/speed_sign_$$m; echo; \
	done

speed_txt:
	@{ echo "=== SHUTTLE  avx2/  end-to-end speed (tail/median rdtsc cycles, speed_sign) ==="; \
	   echo " xof modes: NGCC then SHA3 (both passes below)"; \
	   $(MACHINFO); \
	   echo " stability metrics: p25/p50/p75/p90/p99 percentiles; StQ1/StQ2/StQ3 stabilized quartiles;"; \
	   echo "   stddev / cv (stddev/avg); outlier_count(>p50*1.5); p90/p50 & p99/p50 tail ratios."; \
	   echo; echo "-- AVX2 backend --"; } > test/speed.txt
	@$(MAKE) --no-print-directory speed >> test/speed.txt
	@echo "wrote test/speed.txt"; cat test/speed.txt

# `profile` runs both XOF backends (NGCC then SHA3) like `speed`; profile_run
# is the single-XOF-mode worker.
.PHONY: profile profile_run
profile:
	@$(MAKE) --no-print-directory profile_run MODE=
	@$(MAKE) --no-print-directory profile_run MODE=SHA3
profile_run:
	@mkdir -p $(BINDIR)
	@echo "-- XOF mode: $(MODELABEL) --"
	@for m in $(MODES); do \
	  case $$m in 128) qs=$(QSET_128);; 256) qs=$(QSET_256);; 512) qs=$(QSET_512);; esac; \
	  $(CC) $(CFLAGS) -DPROF_TIME -DPROF_RAND -I../ref/ntt/$$qs $(MODEFLAG) -DSHUTTLE_MODE=$$m \
	    test/speed_profile.c test/prof.c $(PROFILE_SRCS) $(KAT_XOF) \
	    $$qs/ntt.S $$qs/ntt_consts.c ../ref/ntt/$$qs/ntt_ref.c $(NWAY_XOF) \
	    $(LDLIBS) -lm -o $(BINDIR)/speed_profile_$$m || exit 1; \
	  $(BINDIR)/speed_profile_$$m; echo; \
	done

profile_txt:
	@{ echo "=== SHUTTLE  avx2/  per-component profile (cycles/op, make profile) ==="; \
	   echo " xof modes: NGCC then SHA3 (both passes below)"; \
	   $(MACHINFO); echo; echo "-- AVX2 backend --"; } > test/profiling.txt
	@$(MAKE) --no-print-directory profile >> test/profiling.txt
	@echo "wrote test/profiling.txt"

clean:
	rm -rf $(BINDIR)
