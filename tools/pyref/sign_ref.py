#!/usr/bin/env python3
"""sign_ref.py -- end-to-end KeyGen / Sign / Verify mirror for the SHUTTLE
Python reference.  Byte-exact to ref/sign.c (orchestration) + ref/polyvec.c
(producers) + ref/rounding.c + ref/irs.c + ref/packing.c.

  keygen(seed)            -> (pk, sk)        == crypto_sign_keypair_xi
  sign(sk, msg, rnd)      -> sig             == crypto_sign_signature_rnd
  verify(pk, msg, sig)    -> bool            == (crypto_sign_verify == 0)

XOF MODE is selected by the `sha3` flag (True = SHA3_MODE SHAKE128/256;
False = NGCC_MODE SM3 DRBG).  The default rANS sig path is used (set raw=True
for the -DSIG_RAW fixed-length path).
"""
from params import params
from reduce_ref import Reduce
from ntt_ref import NTT
from packing_ref import Pack, poly_to_bytes, bytes_to_poly, ct_range_reject
from rounding_ref import Rounding
from sampler_ref import cdt_scan96, rcdt_tables
from gauss_ref import (gauss_chunk, noise_minibatch,
                       MINIBATCH_RAND_BYTES, NOISE_MINIBATCH_RAND_BYTES)
from irs_ref import IRS
import xof_ref
import rans_ref


# ---- per-set RCDT noise-table selection (sampler.h) ----
_NOISE_SEL = {
    128: ("noise085", 9, "noise085", 9),
    256: ("noise090", 10, "noise100", 11),
    512: ("noise090", 10, "noise090", 10),
}


class Shuttle:
    def __init__(self, set_id, sha3=True, raw=False):
        self.p = params(set_id)
        self.set_id = set_id
        self.sha3 = sha3
        self.raw = raw
        self.red = Reduce(set_id)
        self.ntt = NTT(set_id)
        self.pack = Pack(set_id)
        self.rnd = Rounding(set_id)
        self.irs = IRS(set_id)
        self._rcdt = rcdt_tables()
        # Right-sized per-squeeze blocks (mirror ref/polyvec.h
        # gauss_block_bytes): each block is ONE squeeze off the lane's
        # persisted ctx (single init, no refill re-init), so the block is the
        # EXACT minimum holding one logical unit -- no granularity rounding,
        # no +64 slack.  Tag-tuned:
        #   SampleY (tag 0x08): GAUSS_BLOCK_Y =
        #       SIGN_BYTES_PER_CHUNK + 8-byte padding + SAMPLE_Y_RAND(676)
        #   ExpandS (tag 0x03): GAUSS_BLOCK_S = NOISE_MINIBATCH_RAND_BYTES(392)
        kvecn_16 = self.p["KVEC"] * self.p["N"] // 16
        self.SIGN_BYTES_PER_CHUNK = (kvecn_16 + 7) // 8
        self.GAUSS_BLOCK_Y = (self.SIGN_BYTES_PER_CHUNK + 8
                              + MINIBATCH_RAND_BYTES + 4)
        self.GAUSS_BLOCK_S = NOISE_MINIBATCH_RAND_BYTES

    # ---- XOF helpers ----
    def _xof256_once(self, seed, nbytes):
        return xof_ref.xof256_init(self.sha3, seed).squeeze(nbytes)

    # ================================================================ #
    #  Producers (polyvec.c)                                           #
    # ================================================================ #
    def expand_seeds(self, xi, kappa):
        """T = ExpandSeeds; absorb 0x00||xi||LE16(EM)||LE32(kappa); squeeze
        5*LAMBDA/8 bytes."""
        p = self.p
        inb = (bytes([0x00]) + bytes(xi)
               + p["EM"].to_bytes(2, "little") + kappa.to_bytes(4, "little"))
        return self._xof256_once(inb, 5 * p["LAMBDA"] // 8)

    def expand_signing_seeds(self, K, rnd, mu, kappa):
        p = self.p
        inb = (bytes([0x01]) + bytes(K) + bytes(rnd) + bytes(mu)
               + kappa.to_bytes(4, "little"))
        return self._xof256_once(inb, p["SEEDBYTES"])

    def expand_a(self, seedA):
        """(agen, hAgen) = ExpandA.  Returns (agen[EM][N], hAgen[EM*ELL][N]),
        each poly is canonical-order NTT-domain uint16 coeffs in [0,q)."""
        p = self.p
        q, n = p["Q"], p["N"]
        mask = (1 << p["DQ_BITS"]) - 1
        na = p["EM"] * n
        nh = p["EM"] * p["ELL"] * n
        wa = na // 16
        wh = nh // 16
        abar = [0] * na
        hbar = [0] * nh
        for t in range(16):
            us = xof_ref.UniformStream(
                self.sha3, 0x02, seedA, t,
                xof_ref.uniform_draw(self.sha3, p))
            self._uniform_reject_chunk(us, abar, t * wa, wa, mask, q, p["BQ"])
            self._uniform_reject_chunk(us, hbar, t * wh, wh, mask, q, p["BQ"])
        agen = [abar[i * n:(i + 1) * n] for i in range(p["EM"])]
        hAgen = [hbar[i * n:(i + 1) * n] for i in range(p["EM"] * p["ELL"])]
        return agen, hAgen

    @staticmethod
    def _uniform_reject_chunk(us, dst, off, count, mask, q, bq):
        for k in range(count):
            while True:
                a = us.next_candidate(bq, mask)
                if a < q:
                    break
            dst[off + k] = a

    def expand_s(self, seedsk):
        """(s, e) = ExpandS.  Returns (s[ELL][N], e[EM][N]) signed coeffs."""
        p = self.p
        n, ELL, EM = p["N"], p["ELL"], p["EM"]
        ns, ne = ELL * n, EM * n
        ws, we = ns // 16, ne // 16
        sbar = [0] * ns
        ebar = [0] * ne
        sname, sentries, ename, eentries = _NOISE_SEL[self.set_id]
        Zs, Ze = self._rcdt[sname], self._rcdt[ename]
        for t in range(16):
            gs = xof_ref.GaussStream(self.sha3, 0x03, seedsk, t,
                                     self.GAUSS_BLOCK_S)
            dst = []
            while len(dst) < ws:
                noise_minibatch(gs, dst, ws, Zs, sentries)
            for i in range(ws):
                sbar[t * ws + i] = dst[i]
            dst = []
            while len(dst) < we:
                noise_minibatch(gs, dst, we, Ze, eentries)
            for i in range(we):
                ebar[t * we + i] = dst[i]
        s = [sbar[i * n:(i + 1) * n] for i in range(ELL)]
        e = [ebar[i * n:(i + 1) * n] for i in range(EM)]
        return s, e

    def sample_c(self, seedC):
        """c = SampleC: partial Fisher-Yates over the binary challenge."""
        p = self.p
        n, tau = p["N"], p["TAU"]
        mask = (1 << p["DN_BITS"]) - 1
        bn = p["BN"]
        c = [0] * n
        # ONE xof256 init (tag||seedC||LE16(0)); the stream is advanced by
        # repeated fixed-size SAMPLEC_DRAW squeezes off the same persisted
        # ctx (no refill re-init), mirroring ref/polyvec.c sample_c.
        nonce = bytes([0x07]) + bytes(seedC) + (0).to_bytes(2, "little")
        draw = xof_ref.samplec_draw(self.sha3, p)
        ctx = xof_ref.xof256_init(self.sha3, nonce)
        block = b""
        pos, avail = 0, 0
        for i in range(n - tau, n):
            while True:
                if pos + bn > avail:
                    block = ctx.squeeze(draw)
                    pos, avail = 0, draw
                j = 0
                for b in range(bn):
                    j |= block[pos + b] << (8 * b)
                j &= mask
                pos += bn
                if j <= i:
                    break
            c[i] = c[j]
            c[j] = 1
        return c

    def sample_y(self, seedY):
        """y = SampleY: KVEC*n wide-Gaussian coeffs over 16 lanes."""
        p = self.p
        n = p["N"]
        ntot = p["KVEC"] * n
        wy = ntot // 16
        ybar = [0] * ntot
        Z = self._rcdt["Z"]
        for t in range(16):
            gs = xof_ref.GaussStream(self.sha3, 0x08, seedY, t,
                                     self.GAUSS_BLOCK_Y,
                                     MINIBATCH_RAND_BYTES + 4)
            chunk = gauss_chunk(gs, wy, Z)
            for i in range(wy):
                ybar[t * wy + i] = chunk[i]
        return [ybar[i * n:(i + 1) * n] for i in range(p["KVEC"])]

    # ================================================================ #
    #  Cached matrix build (sign.c build_cached_matrix)                #
    # ================================================================ #
    def _build_cached_matrix(self, b, agen, hAgen):
        """bhat[EM] = NTT((b - a_gen) mod q); Ahat[EM*ELL] = hAgen (NTT-dom)."""
        p = self.p
        bhat = []
        for i in range(p["EM"]):
            col = [self.red.freeze(b[i][k] - agen[i][k]) for k in range(p["N"])]
            bhat.append(self.ntt.ntt(col))
        Ahat = [list(h) for h in hAgen]
        return bhat, Ahat

    # ================================================================ #
    #  KeyGen (sign.c keygen_from_xi)                                  #
    # ================================================================ #
    def keygen(self, xi):
        p = self.p
        n, ELL, EM = p["N"], p["ELL"], p["EM"]
        kappa = 0
        for _ in range(1000):
            kappa += 1                                  # (K4) increment BEFORE
            T = self.expand_seeds(xi, kappa)
            seedA = T[:p["SEEDBYTES"]]
            seedsk = T[p["SEEDBYTES"]:p["SEEDBYTES"] + p["CHALLENGESEEDBYTES"]]
            masterK = T[p["SEEDBYTES"] + p["CHALLENGESEEDBYTES"]:
                        p["SEEDBYTES"] + 2 * p["CHALLENGESEEDBYTES"]]
            agen, hAgen = self.expand_a(seedA)
            s, e = self.expand_s(seedsk)
            # Step 5: b0 = a_gen + iNTT(A_gen o NTT(s)) + e (mod q).
            shat = [self.ntt.ntt([self.red.freeze(s[j][k]) for k in range(n)])
                    for j in range(ELL)]
            b0 = []
            for i in range(EM):
                acc = None
                for j in range(ELL):
                    prod = self.ntt.pointwise(hAgen[i * ELL + j], shat[j])
                    if acc is None:
                        acc = prod
                    else:
                        acc = [self.red.addm16(acc[k], prod[k]) for k in range(n)]
                th = self.ntt.invntt_tomont(acc)
                b0.append([self.red.freeze(agen[i][k] + th[k] + e[i][k])
                           for k in range(n)])
            # Steps 6-9: b = RoundB(b0); e' = e + (b-b0) bmodpm q.
            b, ep = self.rnd.roundB_update_s2(b0, e)
            # Step 10: norm-window gate over StretchS(1, s, e').
            full = [[1] + [0] * (n - 1)] + [list(s[j]) for j in range(ELL)] \
                + [list(ep[j]) for j in range(EM)]
            stretched = self.rnd.stretch_s(full)
            if not self.rnd.keygen_norm_ok(stretched):
                continue                                 # (K4) loop, kappa++
            # Steps 11-13: pkEncode, HashPK(tr), skEncode.
            pk = self.pack.pack_pk(seedA, b)
            tr = self._xof256_once(bytes([0x05]) + pk, p["CHALLENGESEEDBYTES"])
            sk = self.pack.pack_sk(seedA, b, masterK, tr, s, ep)
            return pk, sk
        raise RuntimeError("keygen: norm window never accepted")

    # ================================================================ #
    #  Sign (sign.c sign_internal)                                     #
    # ================================================================ #
    def sign(self, sk, msg, rnd):
        p = self.p
        n, ELL, EM = p["N"], p["ELL"], p["EM"]
        KVEC, Z1LEN = p["KVEC"], p["Z1LEN"]
        seedA, b, masterK, tr, s, ep, fail = self.pack.unpack_sk(sk)
        assert fail == 0, "skDecode failed"
        # sk_full = [1, s, e']^T
        sk_full = [[1] + [0] * (n - 1)] + [list(s[j]) for j in range(ELL)] \
            + [list(ep[j]) for j in range(EM)]
        agen, hAgen = self.expand_a(seedA)
        bhat, Ahat = self._build_cached_matrix(b, agen, hAgen)
        # mu = HashMsg(0x06 || tr || M).
        mu = self._xof256_once(bytes([0x06]) + bytes(tr) + bytes(msg),
                               p["CHALLENGESEEDBYTES"])
        sk_tilde = self.rnd.stretch_s(sk_full)
        kappa = 0
        for _ in range(1000):
            seedY = self.expand_signing_seeds(masterK, rnd, mu, kappa)
            kappa += 1                                   # (K4) ++ AFTER use
            y = self.sample_y(seedY)
            yp = self.rnd.compress_y(y)
            comY = self.rnd.mat_mul_2q(yp, bhat, Ahat)
            comY_0 = [[self.rnd.lsb_coeff(comY[j][k]) for k in range(n)]
                      for j in range(EM)]
            comY_h = [[self.rnd.highbits_reduced(comY[j][k]) for k in range(n)]
                      for j in range(EM)]
            # seed_c = HashCh(0x04 || EncodeCom(w_h, w_0) || mu).
            enc = self.pack.encode_com_vec(comY_h, comY_0)
            seedC = self._xof256_once(bytes([0x04]) + enc + bytes(mu),
                                      p["CHALLENGESEEDBYTES"])
            c = self.sample_c(seedC)
            # FRESH IRS ctx: 0x09 || seed_y; bulk draw TAU*18.
            irs_buf = self._xof256_once(bytes([0x09]) + bytes(seedY),
                                        p["TAU"] * 18)
            z_tilde = self.irs.reject_sample(irs_buf, y, c, sk_tilde)
            z = self.rnd.compress_y(z_tilde)
            z1 = [z[j] for j in range(Z1LEN)]
            z2 = [z[Z1LEN + j] for j in range(EM)]
            hint = self.rnd.make_hint(comY, z2)
            # z2' via the VERIFIER reconstruction (mirror Verify exactly).
            comY0p_sig = self.rnd.recon_comY0p(z1[0], c)
            comY_tilde_sig = self.rnd.mat_mul_z1_2q(z1, c, bhat, Ahat)
            wh_chk, z2p = self.rnd.use_hint(hint, comY_tilde_sig, comY0p_sig)
            if not self.rnd.response_norm_ok(z1, z2p):
                continue                                 # (K4) kappa advanced
            # sigEncode.
            if self.raw:
                return self.pack_sig_raw(seedC, z1, hint)
            sig = self.pack_sig(seedC, z1, hint)
            if sig is not None:
                return sig
            # rANS bottom -> restart with kappa advanced.
            continue
        raise RuntimeError("sign: loop cap hit")

    # ================================================================ #
    #  Verify (sign.c crypto_sign_verify)                              #
    # ================================================================ #
    def verify(self, pk, msg, sig):
        p = self.p
        n, ELL, EM = p["N"], p["ELL"], p["EM"]
        Z1LEN = p["Z1LEN"]
        exp_len = self._sig_raw_len() if self.raw else self._sig_packed_len()
        if len(sig) != exp_len:
            return False
        seedA, b, rc = self.pack.unpack_pk(pk)
        if rc != 0:
            return False
        dec = self.unpack_sig_raw(sig) if self.raw else self.unpack_sig(sig)
        if dec is None:
            return False
        seedC, z1, hint = dec
        tr = self._xof256_once(bytes([0x05]) + pk, p["CHALLENGESEEDBYTES"])
        mu = self._xof256_once(bytes([0x06]) + bytes(tr) + bytes(msg),
                               p["CHALLENGESEEDBYTES"])
        c = self.sample_c(seedC)
        agen, hAgen = self.expand_a(seedA)
        bhat, Ahat = self._build_cached_matrix(b, agen, hAgen)
        comY0p0 = self.rnd.recon_comY0p(z1[0], c)
        comY_tilde = self.rnd.mat_mul_z1_2q(z1, c, bhat, Ahat)
        comY_h, z2p = self.rnd.use_hint(hint, comY_tilde, comY0p0)
        enc = self.pack.encode_com_vec(comY_h, comY0p_pad(comY0p0, EM, n))
        seedCp = self._xof256_once(bytes([0x04]) + enc + bytes(mu),
                                   p["CHALLENGESEEDBYTES"])
        return (bytes(seedCp) == bytes(seedC)
                and self.rnd.response_norm_ok(z1, z2p))

    # ================================================================ #
    #  Signature packing (packing.c)                                   #
    # ================================================================ #
    def _sig_raw_len(self):
        p = self.p
        return (p["CHALLENGESEEDBYTES"] + p["Z1LEN"] * 2 * p["N"]
                + p["EM"] * p["POLYWH_PACKEDBYTES"])

    def pack_sig_raw(self, seedC, z1, hint):
        p = self.p
        out = bytearray(seedC)
        for i in range(p["Z1LEN"]):
            for k in range(p["N"]):
                v = z1[i][k] & 0xFFFF
                out.append(v & 0xFF)
                out.append((v >> 8) & 0xFF)
        for i in range(p["EM"]):
            out += poly_to_bytes(hint[i], p["DH_BITS"])
        return bytes(out)

    def unpack_sig_raw(self, sig):
        p = self.p
        cur = 0
        seedC = bytes(sig[cur:cur + p["CHALLENGESEEDBYTES"]])
        cur += p["CHALLENGESEEDBYTES"]
        z1 = []
        for i in range(p["Z1LEN"]):
            poly = []
            for k in range(p["N"]):
                u = sig[cur + 2 * k] | (sig[cur + 2 * k + 1] << 8)
                poly.append(u - (1 << 16) if u >= (1 << 15) else u)
            z1.append(poly)
            cur += 2 * p["N"]
        hint = []
        fail = 0
        whb = p["POLYWH_PACKEDBYTES"]
        for i in range(p["EM"]):
            h = bytes_to_poly(sig[cur:cur + whb], p["DH_BITS"], p["N"])
            for v in h:
                fail |= ct_range_reject(v, 0, p["HH"] - 1)
            hint.append(h)
            cur += whb
        if fail:
            return None
        return seedC, z1, hint

    # ---- rANS sig (packing.c pack_sig / unpack_sig) ----
    def _rans_consts(self):
        p = self.p
        import re as _re
        txt = open(_REF_RANS_H).read()
        def get(name):
            blocks = _re.split(r"#if SHUTTLE_MODE == (\d+)", txt)
            for i in range(1, len(blocks), 2):
                if int(blocks[i]) == self.set_id:
                    m = _re.search(r"#\s*define\s+%s\s+(\d+)" % name, blocks[i + 1])
                    if m:
                        return int(m.group(1))
            m = _re.search(r"#\s*define\s+%s\s+(\d+)" % name, txt)
            return int(m.group(1))
        return (get("RANS_B0"), get("RANS_BS"), get("RANS_RESERVED_BYTES"))

    def _sig_packed_len(self):
        p = self.p
        b0, bs, reserved = self._rans_consts()
        z0lo = (p["N"] * b0 + 7) // 8
        zslo = (p["ELL"] * p["N"] * bs + 7) // 8
        return p["CHALLENGESEEDBYTES"] + (2 + reserved) + z0lo + zslo

    @staticmethod
    def _split_z(z, b):
        head = z >> b                                 # arithmetic shift
        low = z & ((1 << b) - 1)
        return head, low

    def pack_sig(self, seedC, z1, hint):
        p = self.p
        n, ELL, EM = p["N"], p["ELL"], p["EM"]
        b0, bs, reserved = self._rans_consts()
        # gather symbols (heads).
        q0 = [self._split_z(z1[0][k], b0)[0] for k in range(n)]
        qs = []
        for i in range(ELL):
            for k in range(n):
                qs.append(self._split_z(z1[i + 1][k], bs)[0])
        hh = []
        for i in range(EM):
            for k in range(n):
                hh.append(hint[i][k])
        try:
            com = rans_ref.encode(self.set_id, q0, qs, hh)
        except ValueError:
            return None                               # out-of-support -> bottom
        rlen = len(com)
        if rlen > reserved:
            return None
        out = bytearray(seedC)
        out.append(rlen & 0xFF)
        out.append((rlen >> 8) & 0xFF)
        out += com
        out += bytes(reserved - rlen)
        # raw low-bit body R.
        out += self._pack_zlow(z1[0], b0)
        for i in range(ELL):
            out += self._pack_zlow(z1[i + 1], bs)
        return bytes(out)

    def unpack_sig(self, sig):
        p = self.p
        n, ELL, EM = p["N"], p["ELL"], p["EM"]
        b0, bs, reserved = self._rans_consts()
        cur = 0
        seedC = bytes(sig[cur:cur + p["CHALLENGESEEDBYTES"]])
        cur += p["CHALLENGESEEDBYTES"]
        rlen = sig[cur] | (sig[cur + 1] << 8)
        cur += 2
        com_region = sig[cur:cur + reserved]
        if rlen > reserved:
            return None
        if any(com_region[pad] != 0 for pad in range(rlen, reserved)):
            return None
        try:
            q0, qs, hh = rans_ref.decode(self.set_id, bytes(com_region[:rlen]),
                                         n, ELL * n, EM * n)
        except ValueError:
            return None
        cur += reserved
        z1 = [[0] * n for _ in range(p["Z1LEN"])]
        for k in range(n):
            z1[0][k] = q0[k]
        for i in range(ELL):
            for k in range(n):
                z1[i + 1][k] = qs[i * n + k]
        hint = []
        fail = 0
        for i in range(EM):
            h = []
            for k in range(n):
                v = hh[i * n + k]
                fail |= ct_range_reject(v, 0, p["HH"] - 1)
                h.append(v)
            hint.append(h)
        if fail:
            return None
        # raw low-bit body.
        z0lo = (n * b0 + 7) // 8
        self._unpack_zlow(z1[0], sig[cur:cur + z0lo], b0)
        cur += z0lo
        zslo_each = (n * bs + 7) // 8
        for i in range(ELL):
            self._unpack_zlow(z1[i + 1], sig[cur:cur + zslo_each], bs)
            cur += zslo_each
        # re-encode injectivity check (K15).
        re_sig = self.pack_sig(seedC, z1, hint)
        if re_sig is None or re_sig != bytes(sig):
            return None
        return seedC, z1, hint

    def _pack_zlow(self, poly, b):
        n = self.p["N"]
        mask = (1 << b) - 1
        out = bytearray()
        acc = 0
        accbits = 0
        for k in range(n):
            _head, low = self._split_z(poly[k], b)
            acc |= (low & mask) << accbits
            accbits += b
            while accbits >= 8:
                out.append(acc & 0xFF)
                acc >>= 8
                accbits -= 8
        if accbits > 0:
            out.append(acc & 0xFF)
        return bytes(out)

    def _unpack_zlow(self, poly, blob, b):
        n = self.p["N"]
        mask = (1 << b) - 1
        acc = 0
        accbits = 0
        inpos = 0
        for k in range(n):
            while accbits < b:
                acc |= blob[inpos] << accbits
                inpos += 1
                accbits += 8
            low = acc & mask
            acc >>= b
            accbits -= b
            poly[k] = (poly[k] << b) | low


def comY0p_pad(comY0p0, EM, n):
    """Build the EM-poly comY0p vector with only the first slot nonzero."""
    out = [list(comY0p0)] + [[0] * n for _ in range(EM - 1)]
    return out


# ref/rans.h path for the rANS structural constants.
import os as _os
_REF_RANS_H = _os.path.normpath(_os.path.join(
    _os.path.dirname(_os.path.abspath(__file__)), "..", "..", "ref", "rans.h"))


def _selftest():
    print("sign_ref.py: import OK (run xcheck_sign.py for the byte-exact "
          "cross-check against the C oracle)")
    return 0


if __name__ == "__main__":
    raise SystemExit(_selftest())
