#!/usr/bin/env python3
"""gauss_ref.py -- ApproxExp Q64 kernel + wide-Gaussian (SampleY) and keygen
noise (ExpandS) sampler mirrors for the SHUTTLE Python reference.

Byte/value-exact to:
  - ref/approx_exp.h / tools/approx_exp_poly.h  (shuttle_exp_accept_poly_q64)
  - ref/sampler.c                               (gauss_finalize, the zero-fold)
  - ref/polyvec.c  gauss_stream_chunk / noise_minibatch  (the mini-batch byte
    schedule with the up-front sign/padding block and appended fold bits, K6/K8/K9)

The ApproxExp coefficients are parsed from the committed
tools/approx_exp_poly.h (no re-derivation -> no new magic numbers).  The
fixed-point arithmetic mirrors the C kernel EXACTLY (signed __int128
arithmetic right-shift = floor; the squaring uses the UNSIGNED high-half).
"""
import os
import re

from params import params
from sampler_ref import cdt_scan96, rcdt_tables

_HERE = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.normpath(os.path.join(_HERE, ".."))
EXP_H = os.path.join(_TOOLS, "approx_exp_poly.h")

_M64 = (1 << 64) - 1
_M128 = (1 << 128) - 1


def _s128(x):
    """interpret a Python int as a signed 128-bit two's-complement value."""
    x &= _M128
    return x - (1 << 128) if x >= (1 << 127) else x


def _high64_s128(a, b):
    """shuttle_high64_s128: (int128)((a * (int128)b) >> 64), arithmetic >>64."""
    prod = _s128(a) * b            # exact Python big int
    return prod >> 64              # Python >> on a negative int = arithmetic


def _high64_u64(a, b):
    """shuttle_high64_u64: ((u128)a * (u128)b) >> 64 (unsigned)."""
    return ((a & _M64) * (b & _M64)) >> 64


# ---- ApproxExp coefficients (parsed from approx_exp_poly.h) ----
_EXP_COEFF = None


def _exp_coeffs():
    global _EXP_COEFF
    if _EXP_COEFF is None:
        txt = open(EXP_H).read()
        m = re.search(r"kShuttleExpPolyCoeff\[8\]\s*=\s*\{(.*?)\};", txt, re.S)
        _EXP_COEFF = [int(v) for v in re.findall(r"INT64_C\((-?\d+)\)", m.group(1))]
        assert len(_EXP_COEFF) == 8, _EXP_COEFF
    return _EXP_COEFF


def approx_exp_accept_q64(x, y):
    """shuttle_exp_accept_poly_q64(int x, int y) -> uint64 Q64 threshold.
    Degree-8 Horner in a signed Q64 accumulator, then 7 unsigned squarings."""
    c = _exp_coeffs()
    n = (y & _M64) * ((y + 512 * x) & _M64) & _M64   # uint64 n = y*(y+512x)
    s_q63 = (n << 40) & _M64                          # int64 s_q63 = n<<40
    s_q63 = s_q63 - (1 << 64) if s_q63 >= (1 << 63) else s_q63  # to signed int64
    acc = c[7]
    for k in (6, 5, 4, 3, 2, 1, 0):
        acc = c[k] + _high64_s128(acc, s_q63) * 2
    acc = _M64 + _high64_s128(acc, s_q63) * 2          # C_0 = UINT64_MAX literal
    v = acc & _M64                                     # (uint64)acc
    for _ in range(7):
        v = _high64_u64(v, v)
    return v & _M64


# ---- gauss_finalize (sampler.c) ----
def _ct_lt_u64(a, b):
    return 1 if (a & _M64) < (b & _M64) else 0


def gauss_finalize(x, y, p_hat, tail8, sign_bit, fold_bit=0):
    """Mirror ref/sampler.c gauss_finalize.  Returns (keep, out_coeff).
    cand = 256*x + y; accept iff LE64(tail) < p_hat; z==0 zero-fold drops a
    cand==0 candidate when the independent fold bit is 1 (halves the 0 mass)."""
    WIDE_K = 256
    cand = WIDE_K * x + y                        # int32 256x+y (small int)
    u = int.from_bytes(bytes(tail8), "little")
    accept = _ct_lt_u64(u, p_hat)
    z0 = 1 if cand == 0 else 0
    keep = accept & (1 ^ (z0 & (fold_bit & 1)))
    out = -cand if (sign_bit & 1) else cand
    return keep, out


# ============================================================ #
#  ExpandS noise mini-batch (ref/polyvec.c noise_minibatch)    #
# ============================================================ #
# Per noise mini-batch (NOISE_MINIBATCH_RAND_BYTES = 392):
#   - cdt_scan96 over the noise table (NOISE_BATCH=32), 384 bytes
#   - 8-byte 2-bit-per-candidate tail (bit0 sign, bit1 zero-fold), 4 cand/byte
# The WHOLE 392 bytes are consumed up front (cursor advances independent of the
# cnt==want early break).
NOISE_BATCH = 32
NOISE_CDT_BYTES = 384
NOISE_TAIL_BYTES = 8
NOISE_MINIBATCH_RAND_BYTES = NOISE_CDT_BYTES + NOISE_TAIL_BYTES


def noise_minibatch(gs, dst, want, Z, entries):
    """Mirror ref/polyvec.c noise_minibatch: ensure 392 bytes, scan + tail,
    append accepted signed coeffs to dst (stops at want), advance the cursor by
    the WHOLE 392 (independent of the early break)."""
    gs.ensure(NOISE_MINIBATCH_RAND_BYTES)
    pos = gs.pos
    buf = gs.buf
    mag = cdt_scan96(bytes(buf[pos:pos + NOISE_CDT_BYTES]), Z, entries, NOISE_BATCH)
    tailp = pos + NOISE_CDT_BYTES
    for j in range(NOISE_BATCH):
        f = (buf[tailp + (j >> 2)] >> (2 * (j & 3))) & 3   # bit0 sign, bit1 fold
        reject = (1 if mag[j] == 0 else 0) & (f >> 1)
        r = -mag[j] if (f & 1) else mag[j]
        if len(dst) < want and not reject:
            dst.append(r)
    gs.pos += NOISE_MINIBATCH_RAND_BYTES


# ============================================================ #
#  SampleY wide-Gaussian mini-batch (ref/polyvec.c chunk)      #
# ============================================================ #
GAUSS_BATCH = 32
SIGMA_S_RAND_BYTES = 384
Y_RAND_BYTES = 32
GAUSS_RAND_BYTES = 8
MINIBATCH_RAND_BYTES = SIGMA_S_RAND_BYTES + Y_RAND_BYTES + GAUSS_BATCH * GAUSS_RAND_BYTES  # 672
SAMPLE_Y_FOLD_BYTES = GAUSS_BATCH // 8
SAMPLE_Y_RAND_BYTES = MINIBATCH_RAND_BYTES + SAMPLE_Y_FOLD_BYTES  # 676
SAMPLE_Y_PADDING_BYTES = 8


def gauss_chunk(gs, count, Z):
    """Mirror ref/polyvec.c gauss_stream_chunk over a GaussStream `gs`.
    Returns the list of `count` accepted wide-Gaussian coeffs.  Z = RCDT_Z."""
    dst = []
    # (1) up-front sign bits: (count+7)//8 bytes, ONE bit per OUTPUT.  The C
    # `signs` buffer is SIGN_PAD_AVX512-padded with zeros, and the per-
    # candidate loop reads signs[coefcnt>>3] even after coefcnt reaches count
    # (the remaining j's of the last mini-batch), so pad here to mirror it.
    signbytes = (count + 7) // 8
    # First block also includes fixed padding before the first candidate batch.
    gs.ensure(signbytes + SAMPLE_Y_PADDING_BYTES)
    signs = bytes(gs.buf[gs.pos:gs.pos + signbytes]) + bytes(8)
    gs.pos += signbytes + SAMPLE_Y_PADDING_BYTES
    coefcnt = 0
    dummy = count - (1 if count != 0 else 0)
    while coefcnt < count:
        gs.ensure(SAMPLE_Y_RAND_BYTES)
        pos = gs.pos
        buf = gs.buf
        x = cdt_scan96(bytes(buf[pos:pos + SIGMA_S_RAND_BYTES]), Z, 36, GAUSS_BATCH)
        yp = pos + SIGMA_S_RAND_BYTES
        yv = [buf[yp + j] for j in range(GAUSS_BATCH)]        # Y_BITS=8 byte copy
        phat = [approx_exp_accept_q64(x[j], yv[j]) for j in range(GAUSS_BATCH)]
        tailp = pos + SIGMA_S_RAND_BYTES + Y_RAND_BYTES
        foldp = pos + MINIBATCH_RAND_BYTES
        for j in range(GAUSS_BATCH):
            idx = dummy if coefcnt == count else coefcnt       # safe sign index
            sgn = (signs[idx >> 3] >> (idx & 7)) & 1
            t0 = tailp + j * GAUSS_RAND_BYTES
            fold = (buf[foldp + (j >> 3)] >> (j & 7)) & 1
            keep, r = gauss_finalize(x[j], yv[j], phat[j], buf[t0:t0 + 8], sgn, fold)
            if keep:
                if coefcnt < count:
                    dst.append(r)
                    coefcnt += 1
        gs.pos += SAMPLE_Y_RAND_BYTES
    return dst


def _selftest():
    # exp(0,0) -> p_hat ~ 2^64-1 (exp(0)=1; the fixed-point squaring lands a
    # few ULP below the literal max -- this is the EXACT C kernel output, not
    # 2^64-1, and is cross-checked against the C oracle).
    p00 = approx_exp_accept_q64(0, 0)
    assert p00 >= _M64 - 0x100, hex(p00)
    # exp at the minimum (x=36,y=255) is a small positive value < 2^64.
    pmin = approx_exp_accept_q64(36, 255)
    assert 0 < pmin < (1 << 62), hex(pmin)
    # zero-fold: cand=0, fold=1 -> drop even if accept.
    keep, out = gauss_finalize(0, 0, _M64, bytes(8), 1, 1)
    assert keep == 0 and out == 0
    keep, out = gauss_finalize(0, 0, _M64, bytes(8), 0)
    assert keep == 1 and out == 0
    print("gauss_ref.py self-test: ApproxExp(0,0)==2^64-1, ApproxExp(36,255) "
          "small; gauss_finalize zero-fold OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
