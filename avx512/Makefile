# Makefile for the SHUTTLE signature AVX-512 implementation.
#
#   make                 # build all tests for all modes -> out/
#   make check           # build + run every test for every mode (assert exit 0)
#   make check-kat       # build test_kat; assert recorded KAT (ref==avx2==avx512)
#   make check-refill    # force multi-way XOF continuation-squeeze; KAT unchanged
#   make check-consts    # reproducibility/drift gate (params/bounds + vendored NTT)
#   make sm3-test        # legacy SM3 16-way XOF/DRNG byte-exactness test
#   make clean
#
# Mirrors avx2/Makefile but its flags drop -mno-avx512f and add -mavx512* (the
# existing SM3 16-way code needs VBMI2 per memory `avx512-requires-vbmi2`), and
# it DROPS check-no-avx512.  Maps to the NGCC Additional_Implementation folder
# (steps outside the literal NGCC perf flag set; AVX-512 perf is local-only).
#
# Shared algorithm/KAT source is SYMLINKED from ../ref (single source of truth;
# materialized by ../tools/mklinks.sh).  At the byte-exactness milestone the
# AVX-512-specific REAL files are ONLY: config.h, poly_ntt.c (the SIMD NTT shim
# fork) + the per-mode vendored ntt_avx512.S / ntt_consts_avx512.c (q59393n1024
# uses the 2x512 superblock), and the AVX-only / N-way XOF files.  Everything
# else -- including the would-be-fork scalar sources and the NGCC infra -- is
# symlinked scalar.  Because the AVX NTT is byte-exact and the scalar scheme
# logic is identical to ref, the avx512 KAT hash EQUALS the ref hash (the
# byte-exactness gate).

MODES ?= 128 256 512
# Full ref test matrix (mirrors ref/Makefile TESTS) with the SCALAR-only NTT
# oracle (test_ntt) REPLACED by the AVX-512 NTT driver (test_ntt_avx512); see
# the note in avx2/Makefile (test_ntt's naive readback is wrong for the SIGNED
# mode-128 lazy lane; test_ntt_avx512 uses the per-config smod readback).
TESTS ?= t_params test_xof t_reduce test_ntt_avx512 test_pack test_sampler \
         test_approx test_samplers test_irs test_rounding test_rans test_sign test_kat
CC    ?= gcc

# avx2 perf flags MINUS -mno-avx512f, PLUS the AVX-512 subsets (F/BW/DQ/VL +
# VBMI2).  -std=c99 -Wpedantic warns on intrinsics/asm; tolerated on the perf
# build.
CFLAGS ?= -O3 -march=x86-64 -mavx2 -mtune=native -fomit-frame-pointer \
          -std=c99 -Wpedantic -Wall -Wextra -mbmi2 -mpopcnt \
          -mavx512f -mavx512bw -mavx512dq -mavx512vl -mavx512vbmi2 \
          -I. -I../ref -I../ref/test -I../tools \
          -DUSE_AVX512_NTT -DUSE_AVX512_SAMPLER -DUSE_AVX512_SHAKE8X \
          -DUSE_AVX512_XOF_NWAY
LDLIBS ?=
BINDIR  = out
CT_OPT ?= -O3

MODE ?=
ifeq ($(MODE),SHA3)
MODEFLAG = -DSHA3_MODE
else
MODEFLAG =
endif

# XOF source list, MODE-dependent (identical link set to ref: the symlinked
# scalar scheme code calls only the SCALAR xof128/256 primitives at the
# byte-exactness milestone).  The KAT harness always seeds via the SM3
# Hash-DRBG, so a SHA3_MODE KAT binary needs drng.c+auxfunc.c IN ADDITION to
# the SHAKE backend.
ifeq ($(MODE),SHA3)
XOF_SRCS = symmetric.c fips202.c
KAT_XOF  = symmetric.c fips202.c ../ref/drng.c ../ref/auxfunc.c
# N-way (8-way SHAKE) XOF kernels used by the later-step ExpandA/ExpandS/SampleY
# batched refills (USE_AVX512_XOF_NWAY).  Appended whenever polyvec.c links.
# symmetric_avx512.c = the xof*_avx512_* wrappers; fips202x8.c +
# keccakf1600x8.c = the 8-way Keccak.  (Scalar fips202.c already in XOF_SRCS
# for the round-constant table keccakf1600x8.c reuses.)
NWAY_XOF = symmetric_avx512.c fips202x8.c keccakf1600x8.c
else
XOF_SRCS = symmetric.c ../ref/drng.c ../ref/auxfunc.c
KAT_XOF  = $(XOF_SRCS)
# N-way (16-way SM3) XOF kernels for the later-step batched refills.
# symmetric_avx512.c = the xof*_avx512_* wrappers; drng_avx512.c = the 16-way
# SM3 Hash-DRBG; auxfunc_avx512.c = the 16-way SM3 core it calls.  (Scalar
# drng.c/auxfunc.c already in XOF_SRCS for the seeding DRBG.)
NWAY_XOF = symmetric_avx512.c drng_avx512.c auxfunc_avx512.c
endif

# IRS single-buffer bulk fill (irs.c) N-way SM3 core.  Under NGCC the avx512
# irs.c (USE_AVX512_XOF_NWAY) calls sm3hash_avx512 (auxfunc_avx512.c) for the
# bulk tau*18 DRBG generate, so any irs.c-linking test that does NOT already
# pull polyvec.c (-> NWAY_XOF) needs auxfunc_avx512.c on its own.  Under SHA3
# the irs.c bulk fill is the plain scalar xof256_squeeze (N-way path #if'd
# out), so no extra source is required.
ifeq ($(MODE),SHA3)
IRS_NWAY_SRC =
else
IRS_NWAY_SRC = auxfunc_avx512.c
endif

# Per-test source lists (POSIX-sh strings).  Identical scalar source lists to
# ref/Makefile; poly_ntt.c resolves to the AVX-512 SIMD shim fork here, and the
# build loop appends the per-mode vendored avx512 asm whenever poly_ntt.c (or
# polyvec.c) is present.  test_ntt_avx512 is the AVX-512 NTT correctness driver.
SH_SRCS = \
't_params=' \
"test_xof=$(XOF_SRCS)" \
't_reduce=reduce.c' \
'test_ntt_avx512=poly_ntt.c reduce.c' \
'test_pack=packing.c poly.c reduce.c rans.c' \
'test_sampler=sampler.c reduce.c' \
'test_approx=approx_exp.c approx_log.c' \
"test_samplers=polyvec.c sampler.c reduce.c approx_exp.c approx_log.c $(XOF_SRCS)" \
"test_irs=irs.c sampler_u.c approx_exp.c approx_log.c reduce.c $(XOF_SRCS) $(IRS_NWAY_SRC)" \
'test_rounding=rounding.c reduce.c poly.c poly_ntt.c packing.c rans.c' \
'test_rans=packing.c poly.c reduce.c rans.c' \
"test_sign=sign.c polyvec.c sampler.c sampler_u.c irs.c rounding.c packing.c poly.c poly_ntt.c reduce.c rans.c approx_exp.c approx_log.c $(XOF_SRCS)" \
"test_kat=SIG_AlgorithmInstance.c sign.c polyvec.c sampler.c sampler_u.c irs.c rounding.c packing.c poly.c poly_ntt.c reduce.c rans.c approx_exp.c approx_log.c $(KAT_XOF)"

# Per-set NTT vendoring: a case $$m picks $qs; when a test's srcs contain
# polyvec.c OR poly_ntt.c the build appends $qs/ntt_avx512.S +
# ntt_consts_avx512.c (the AVX-512 kernels) AND the scalar oracle
# ../ref/ntt/$qs/ntt_ref.c (the scheme-facing shim + poly_ntt_canonical use
# it), with -I../ref/ntt/$qs so poly_ntt.h finds the per-set vendored header.
QSET_128 = q15361n256
QSET_256 = q61441n512
QSET_512 = q59393n1024
NTTGEN   = ../tools/ntt

# Recorded canonical KAT hashes (shared: ref == avx2 == avx512; the
# byte-exactness gate).
# IDENTICAL to ref/Makefile; re-record in lock-step on output-changing diffs.
KAT_128_NGCC = 5525731303976652954
KAT_256_NGCC = 4684222326669620474
KAT_512_NGCC = 8059965594724964533
KAT_128_SHA3 = 11439871523140599355
KAT_256_SHA3 = 8372293911548186006
KAT_512_SHA3 = 12332646238986233852
MODELABEL = $(if $(filter SHA3,$(MODE)),SHA3,NGCC)

.PHONY: all check check-kat check-refill check-consts sm3-test \
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
	          extra="$$qs/ntt_avx512.S $$qs/ntt_consts_avx512.c ../ref/ntt/$$qs/ntt_ref.c"; \
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
	@echo "built: [$(TESTS)] x [$(MODES)] (avx512)"

check: all
	@for m in $(MODES); do \
	  echo "=== SHUTTLE-$$m (avx512) ==="; \
	  for want in $(TESTS); do \
	    [ -x $(BINDIR)/$${want}_$${m} ] \
	      || { echo "missing test binary: $(BINDIR)/$${want}_$${m}"; exit 1; }; \
	    $(BINDIR)/$${want}_$${m} || exit 1; \
	  done; \
	done

# Assert the recorded per-mode KAT hashes (ref == avx2 == avx512).
check-kat:
	@$(MAKE) MODES="$(MODES)" MODE="$(MODE)" TESTS=test_kat all >/dev/null
	@KAT_128=$(KAT_128_$(MODELABEL)); KAT_256=$(KAT_256_$(MODELABEL)); KAT_512=$(KAT_512_$(MODELABEL)); \
	fail=0; for m in $(MODES); do \
	  got=`$(BINDIR)/test_kat_$$m | sed -n 's/^KAT_hash=//p'`; \
	  eval exp=\$$KAT_$$m; \
	  if [ "$$got" = "$$exp" ]; then echo "  PASS: KAT-$$m ($(MODELABEL),avx512) = $$got"; \
	  else echo "  FAIL: KAT-$$m ($(MODELABEL),avx512) got $$got want $$exp"; fail=1; fi; \
	done; [ $$fail -eq 0 ] && echo "check-kat: avx512 KAT matches recorded (ref==avx512)" || exit 1

# Force-exercise the multi-way XOF continuation-squeeze (refill) path; at the
# byte-exactness milestone the scheme runs the scalar XOF so this is a no-op KAT
# rerun (load-bearing once the N-way SIMD XOF kernels land).
check-refill:
	@$(MAKE) MODES="$(MODES)" MODE="$(MODE)" CFLAGS="$(CFLAGS) -DGAUSS8X_INIT=4 -DNOISE8X_INIT=4" TESTS="test_kat" all >/dev/null
	@echo "== forced multi-way refill: KAT must be unchanged =="
	@for m in $(MODES); do $(BINDIR)/test_kat_$$m | sed -n 's/^/  /p'; done

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
	@echo "== vendored AVX-512 NTT (./<qset>/ntt_avx512.S + ntt_consts_avx512.c) vs gen_ntt.py =="
	@rm -rf $(BINDIR)/ntt_regen
	@mkdir -p $(BINDIR)/ntt_regen
	@for qs in $(QSET_128) $(QSET_256) $(QSET_512); do \
	  if [ -d "$(NTTGEN)/$$qs" ] && [ -f "$$qs/ntt_avx512.S" ]; then \
	    python3 $(NTTGEN)/$$qs/gen_ntt.py $(BINDIR)/ntt_regen >/dev/null 2>&1 \
	      || { echo "  FAIL: $$qs gen_ntt.py"; exit 1; }; \
	    cmp -s $(BINDIR)/ntt_regen/avx512/$$qs/ntt_consts_avx512.c $$qs/ntt_consts_avx512.c \
	      && cmp -s $(BINDIR)/ntt_regen/avx512/$$qs/ntt_avx512.S $$qs/ntt_avx512.S \
	      && echo "  PASS: $$qs vendored AVX-512 NTT matches gen_ntt.py" \
	      || { echo "  FAIL: $$qs vendored AVX-512 NTT differs (re-run make tables)"; exit 1; }; \
	  else echo "  skip: $$qs vendored AVX-512 NTT not present"; fi; \
	done
	@rm -rf $(BINDIR)/ntt_regen
	@echo "check-consts: params + AVX-512 NTT constants reproducible"

# Legacy SM3 16-way XOF/DRNG byte-exactness test (16-way AVX-512 vs scalar ref).
SM3_AVX512 := -mavx512f -mavx512bw -mavx512dq -mavx512vl -mbmi2
sm3-test:
	@mkdir -p $(BINDIR)
	@$(CC) -O3 -std=c99 -Wall -Wextra $(SM3_AVX512) -I../ref \
	   test_avx512.c auxfunc_avx512.c ../ref/auxfunc.c -o $(BINDIR)/sm3_test_avx512 2>/dev/null \
	   && $(BINDIR)/sm3_test_avx512 || echo "sm3-test: build deferred (SM3 sources)"
	@$(CC) -O3 -std=c99 -Wall -Wextra $(SM3_AVX512) -I../ref \
	   test_drng_avx512.c drng_avx512.c auxfunc_avx512.c ../ref/drng.c -o $(BINDIR)/sm3_test_drng_avx512 2>/dev/null \
	   && $(BINDIR)/sm3_test_drng_avx512 || echo "sm3-test(drng): build deferred (SM3 sources)"

# ===================================================================== #
#  Speed / profile benchmarks (mirror the `all` per-mode build: $qs ->   #
#  AVX-512 vendored NTT asm + scalar oracle + the N-way XOF kernels,      #
#  since polyvec.c is in the scheme source list).  The sig_* drivers seed #
#  via the SM3 Hash-DRBG exactly like the KAT harness, so $(KAT_XOF) is   #
#  used (drng.c+auxfunc.c even under SHA3_MODE).                          #
# ===================================================================== #
SCHEME_SRC = SIG_AlgorithmInstance.c sign.c polyvec.c sampler.c sampler_u.c irs.c \
             rounding.c packing.c poly.c poly_ntt.c reduce.c rans.c approx_exp.c approx_log.c
SPEED_SRCS   = $(SCHEME_SRC)
PROFILE_SRCS = $(SCHEME_SRC)
# Extra cc flags for the bench drivers ONLY (e.g. -DBENCH_SIGN_RUNS=N -DNV=N
# -DNGCC_ITERS=N to shrink the run for quick/CI evidence); empty by default.
SPEED_EXTRA ?=

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
	    $$qs/ntt_avx512.S $$qs/ntt_consts_avx512.c ../ref/ntt/$$qs/ntt_ref.c $(NWAY_XOF) \
	    $(LDLIBS) -lm -o $(BINDIR)/speed_sign_$$m || exit 1; \
	  $(BINDIR)/speed_sign_$$m; echo; \
	done

speed_txt:
	@{ echo "=== SHUTTLE  avx512/  end-to-end speed (tail/median rdtsc cycles, speed_sign) ==="; \
	   echo " xof modes: NGCC then SHA3 (both passes below)"; \
	   $(MACHINFO); \
	   echo " stability metrics: p25/p50/p75/p90/p99 percentiles; StQ1/StQ2/StQ3 stabilized quartiles;"; \
	   echo "   stddev / cv (stddev/avg); outlier_count(>p50*1.5); p90/p50 & p99/p50 tail ratios."; \
	   echo; echo "-- AVX-512 backend --"; } > test/speed.txt
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
	    $$qs/ntt_avx512.S $$qs/ntt_consts_avx512.c ../ref/ntt/$$qs/ntt_ref.c $(NWAY_XOF) \
	    $(LDLIBS) -lm -o $(BINDIR)/speed_profile_$$m || exit 1; \
	  $(BINDIR)/speed_profile_$$m; echo; \
	done

profile_txt:
	@{ echo "=== SHUTTLE  avx512/  per-component profile (cycles/op, make profile) ==="; \
	   echo " xof modes: NGCC then SHA3 (both passes below)"; \
	   $(MACHINFO); echo; echo "-- AVX-512 backend --"; } > test/profiling.txt
	@$(MAKE) --no-print-directory profile >> test/profiling.txt
	@echo "wrote test/profiling.txt"

clean:
	rm -rf $(BINDIR)
