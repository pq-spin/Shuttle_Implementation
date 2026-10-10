#!/usr/bin/env python3
"""xof_ref.py -- the SHUTTLE XOF compatibility layer + 16-stream fill engines
for the Python reference.  Byte-exact to ref/symmetric.c + ref/xof.h and the
ref/polyvec.c stream structs (uniform_stream / gauss_stream).

Two MODEs (ref/xof.h):
  SHA3_MODE : xof128 = SHAKE128 (rate 168), xof256 = SHAKE256 (rate 136),
              each init+absorb_once over the whole (tag||seed||nonce) buffer,
              then incremental rate-buffered squeeze.  hashlib provides both.
  NGCC_MODE : both xof128 and xof256 collapse onto the SM3 Hash-DRBG
              (drng_ref.DRNG): init = instantiate(seed), squeeze = generate.

A `XofCtx` wraps the chosen primitive so the producers (ExpandA / ExpandS /
SampleY / SampleC / IRS) are written once against init+squeeze.
"""
import hashlib

import drng_ref


# ===================================================================== #
#  SHAKE incremental squeeze (mirror Keccak rate-buffered squeeze)      #
# ===================================================================== #
# hashlib.shake_*.digest(n) re-runs from scratch each call, but a continuous
# Keccak squeeze is a single stream.  We emulate the continuous stream by
# squeezing a growing prefix and slicing: digest(total) is byte-stable as the
# squeeze count grows (SHAKE is a prefix-stable stream), so consecutive
# squeezes off the same ctx chain correctly.
class _ShakeCtx:
    def __init__(self, which, seed):
        self.which = which                       # 128 or 256
        self.seed = bytes(seed)
        self.pos = 0                             # bytes already consumed

    def squeeze(self, n):
        total = self.pos + n
        h = hashlib.shake_128() if self.which == 128 else hashlib.shake_256()
        h.update(self.seed)
        out = h.digest(total)[self.pos:total]
        self.pos = total
        return out


# ===================================================================== #
#  NGCC SM3 Hash-DRBG ctx (mirror drng.c via drng_ref)                  #
# ===================================================================== #
class _DrngCtx:
    def __init__(self, seed):
        self.d = drng_ref.DRNG.instantiate(bytes(seed))

    def squeeze(self, n):
        return drng_ref.get_random_number(self.d, n * 8)   # BYTES -> BITS shim


class XofCtx:
    """Unified XOF ctx.  `which` is 128 or 256 (selects the primitive in
    SHA3_MODE; ignored in NGCC_MODE where both collapse onto SM3)."""

    def __init__(self, mode_sha3, which, seed):
        self.mode_sha3 = mode_sha3
        if mode_sha3:
            self.impl = _ShakeCtx(which, seed)
        else:
            self.impl = _DrngCtx(seed)

    def squeeze(self, n):
        return self.impl.squeeze(n)


def xof256_init(mode_sha3, seed):
    return XofCtx(mode_sha3, 256, seed)


def xof128_init(mode_sha3, seed):
    return XofCtx(mode_sha3, 128, seed)


# ===================================================================== #
#  Per-squeeze slice sizes (mirror ref/polyvec.h + ref/polyvec.c)       #
# ===================================================================== #
# Each logical lane stream is opened with ONE XOF.Init
#     nonce = tag || seed || LE16(lane)
# (NO refill counter -- the per-lane refill re-init was removed in SHUTTLE
# commit 16dfdfc) and is then advanced purely by repeated FIXED-SIZE
# squeezes off the SAME persisted ctx.  Under NGCC each squeeze is one SM3
# DRBG Generate that evolves V by one step (independent of the length), so
# a chain of fixed-size squeezes is a proper per-lane stream; under SHAKE it
# is the rate-buffered continuation of one stream.  The per-squeeze byte
# count is byte-determining, hence PINNED identically across
# ref / avx2 / avx512 and mirrored here.
def squeeze_granularity(mode_sha3):
    """XOF_SQUEEZE_GRANULARITY_BYTES (ref/xof.h): SHAKE128 rate vs the
    32-word SM3 DRBG block."""
    return 168 if mode_sha3 else 128


def _ceil_to(bytecount, granularity):
    return ((bytecount + granularity - 1) // granularity) * granularity


def uniform_draw(mode_sha3, p):
    """UNIFORM_DRAW (ref/polyvec.c): ceil-to-granularity of
    2 * (EM*n*(1+ELL)/16) * BQ, the right-sized ExpandA continuation slice."""
    lane_coeffs = p["EM"] * p["N"] * (1 + p["ELL"]) // 16
    return _ceil_to(lane_coeffs * p["BQ"] * 2, squeeze_granularity(mode_sha3))


def samplec_draw(mode_sha3, p):
    """SAMPLEC_DRAW (ref/polyvec.c): ceil-to-granularity of TAU*BN*2, the
    right-sized SampleC continuation slice."""
    return _ceil_to(p["TAU"] * p["BN"] * 2, squeeze_granularity(mode_sha3))


# ===================================================================== #
#  uniform_stream (ExpandA): single init + UNIFORM_DRAW squeeze chain   #
# ===================================================================== #
class UniformStream:
    """Mirror ref/polyvec.c uniform_stream (xof128).  nonce = tag||seed||
    LE16(lane); ONE init, then repeated fixed-size UNIFORM_DRAW squeezes off
    the persisted ctx (us_draw_slice)."""

    def __init__(self, mode_sha3, tag, seed, lane, draw):
        self.mode_sha3 = mode_sha3
        self.tag = tag
        self.seed = bytes(seed)
        self.lane = lane
        self.draw = draw
        self.ctx = xof128_init(mode_sha3, self._nonce())
        self.buf = b""
        self.pos = 0
        self.avail = 0
        self._fill()

    def _nonce(self):
        return (bytes([self.tag]) + self.seed + self.lane.to_bytes(2, "little"))

    def _fill(self):
        """us_draw_slice: one more UNIFORM_DRAW squeeze off the same ctx."""
        self.buf = self.ctx.squeeze(self.draw)
        self.pos = 0
        self.avail = self.draw

    def next_candidate(self, nbytes, mask):
        """us_next_candidate: pull nbytes (BQ), continuing the chain across
        the slice edge."""
        if self.pos + nbytes > self.avail:
            self._fill()
        x = 0
        for i in range(nbytes):
            x |= self.buf[self.pos + i] << (8 * i)
        self.pos += nbytes
        return x & mask


# ===================================================================== #
#  gauss_stream (ExpandS / SampleY): single init + block squeeze chain   #
# ===================================================================== #
class GaussStream:
    """Mirror ref/polyvec.c gauss_stream + gs_fill/gs_ensure.  ONE xof256
    init with nonce = tag||seed||LE16(lane), then every block is one more
    squeeze of the fill-indexed gauss block bytes off the SAME persisted ctx; the
    buffer is a persistent byte array the ensure() memmoves the leftover of."""

    def __init__(self, mode_sha3, tag, seed, lane, block, refill_block=None):
        self.mode_sha3 = mode_sha3
        self.tag = tag
        self.seed = bytes(seed)
        self.lane = lane
        self.block = block               # first gauss_block_bytes(tag)
        self.refill_block = refill_block if refill_block is not None else block
        self.fill_count = 0
        self.ctx = xof256_init(mode_sha3, self._nonce())
        self.buf = bytearray()
        self.pos = 0
        self.avail = 0

    def _nonce(self):
        return (bytes([self.tag]) + self.seed + self.lane.to_bytes(2, "little"))

    def _fill(self):
        # gs_fill: one more block squeeze appended after any leftover.
        bsz = self.block if self.fill_count == 0 else self.refill_block
        chunk = self.ctx.squeeze(bsz)
        if len(self.buf) < self.avail + bsz:
            self.buf.extend(bytes(self.avail + bsz - len(self.buf)))
        self.buf[self.avail:self.avail + bsz] = chunk
        self.avail += bsz
        self.fill_count += 1

    def ensure(self, need):
        if self.avail - self.pos >= need:
            return
        left = self.avail - self.pos
        if left:
            self.buf[0:left] = self.buf[self.pos:self.pos + left]
        self.pos = 0
        self.avail = left
        self._fill()
