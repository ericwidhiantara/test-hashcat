#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Minikey → Private Key → All Addresses (P2PKH, P2SH-P2WPKH, Bech32 P2WPKH)
Usage:
  1) Satu minikey:
     python minikey_to_addresses.py S6c56bnXQiBjk9mqSYE7ykVQ7NzrRy

  2) Dari file (1 minikey per baris) ke CSV:
     python minikey_to_addresses.py input_minikeys.txt output.csv

Minikey validasi (Casascius rule):
- String mulai dengan 'S', panjang tipikal 22, 26, atau 30 (bisa lainnya).
- SHA256(minikey + '?') diawali byte 0x00.
- Private key = SHA256(minikey).
"""

import sys
import os
import csv
import hashlib
import binascii
import struct

# ===== Try backends for secp256k1 =====
_BACKEND = None
try:
    import coincurve
    _BACKEND = "coincurve"
except Exception:
    try:
        import ecdsa
        from ecdsa import SigningKey, SECP256k1
        _BACKEND = "ecdsa"
    except Exception:
        _BACKEND = None

# ===== Base58 / Bech32 helpers =====

ALPHABET = b'123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz'

def b58check_encode(payload: bytes) -> str:
    """Base58Check encode: payload = version + data (+ optional flag) + checksum(4)."""
    checksum = hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]
    data = payload + checksum
    # leading zeros -> '1'
    n_pad = len(data) - len(data.lstrip(b'\x00'))
    num = int.from_bytes(data, 'big')
    enc = bytearray()
    while num > 0:
        num, rem = divmod(num, 58)
        enc.append(ALPHABET[rem])
    enc.extend(b'1' * n_pad)
    return enc[::-1].decode()

def hash160(b: bytes) -> bytes:
    return hashlib.new('ripemd160', hashlib.sha256(b).digest()).digest()

# ---- Bech32 (BIP173) minimal ----
# Based on BIP-0173 reference (Python), simplified for HRP 'bc' only
BECH32_ALPHABET = 'qpzry9x8gf2tvdw0s3jn54khce6mua7l'

def bech32_polymod(values):
    GEN = (0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)
    chk = 1
    for v in values:
        b = (chk >> 25) & 0xff
        chk = ((chk & 0x1ffffff) << 5) ^ v
        for i in range(5):
            chk ^= GEN[i] if ((b >> i) & 1) else 0
    return chk

def bech32_hrp_expand(hrp):
    return [ord(x) >> 5 for x in hrp] + [0] + [ord(x) & 31 for x in hrp]

def bech32_create_checksum(hrp, data):
    values = bech32_hrp_expand(hrp) + data
    polymod = bech32_polymod(values + [0, 0, 0, 0, 0, 0]) ^ 1
    return [(polymod >> 5 * (5 - i)) & 31 for i in range(6)]

def bech32_encode(hrp, data):
    combined = data + bech32_create_checksum(hrp, data)
    return hrp + '1' + ''.join([BECH32_ALPHABET[d] for d in combined])

def convertbits(data, frombits, tobits, pad=True):
    """General power-of-2 base conversion (for 8->5 bits)."""
    acc = 0
    bits = 0
    ret = []
    maxv = (1 << tobits) - 1
    for v in data:
        if v < 0 or (v >> frombits):
            return None
        acc = (acc << frombits) | v
        bits += frombits
        while bits >= tobits:
            bits -= tobits
            ret.append((acc >> bits) & maxv)
    if pad:
        if bits:
            ret.append((acc << (tobits - bits)) & maxv)
    elif bits >= frombits or ((acc << (tobits - bits)) & maxv):
        return None
    return ret

def encode_bech32_p2wpkh(pubkey_hash160: bytes, hrp='bc') -> str:
    # witness version 0 + program = hash160(pubkey) length 20
    data = [0] + convertbits(pubkey_hash160, 8, 5)
    return bech32_encode(hrp, data)

# ===== Minikey validation & conversion =====

def is_valid_minikey(minikey: str) -> (bool, str):
    if not minikey or minikey[0] != 'S':
        return False, "Tidak diawali 'S'"
    # Casascius recommended lengths often 22/26/30, tapi aturan utamanya hash test:
    test = hashlib.sha256((minikey + '?').encode()).digest()
    if test[0] != 0x00:
        return False, "Checksum minikey gagal (SHA256(minikey+'?')[0] != 0x00)"
    return True, "OK"

def minikey_to_privkey(minikey: str) -> bytes:
    return hashlib.sha256(minikey.encode()).digest()

# ===== EC key ops =====

SECP256K1_N = int("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141", 16)

def priv_to_pub_compressed(privkey32: bytes) -> bytes:
    if _BACKEND == "coincurve":
        pk = coincurve.PrivateKey(privkey32)
        return pk.public_key.format(compressed=True)
    elif _BACKEND == "ecdsa":
        sk = SigningKey.from_string(privkey32, curve=SECP256k1)
        vk = sk.get_verifying_key()
        x = vk.to_string("uncompressed")[1:33]  # but ecdsa gives 64B (x|y)
        y = vk.to_string("uncompressed")[33:]
        x_int = int.from_bytes(x, 'big')
        y_int = int.from_bytes(y, 'big')
        prefix = b'\x03' if (y_int & 1) else b'\x02'
        return prefix + x_int.to_bytes(32, 'big')
    else:
        raise RuntimeError("Tidak menemukan backend EC. Install 'ecdsa' atau 'coincurve'.")

def priv_to_pub_uncompressed(privkey32: bytes) -> bytes:
    if _BACKEND == "coincurve":
        pk = coincurve.PrivateKey(privkey32)
        return pk.public_key.format(compressed=False)  # 0x04 + X(32) + Y(32)
    elif _BACKEND == "ecdsa":
        sk = SigningKey.from_string(privkey32, curve=SECP256k1)
        vk = sk.get_verifying_key()
        # ecdsa outputs 64 bytes (x|y)
        xy = vk.to_string()
        return b'\x04' + xy
    else:
        raise RuntimeError("Tidak menemukan backend EC. Install 'ecdsa' atau 'coincurve'.")

def wif_from_priv(privkey32: bytes, compressed: bool) -> str:
    # mainnet: 0x80 + priv [+ 0x01 jika compressed]
    payload = b'\x80' + privkey32 + (b'\x01' if compressed else b'')
    return b58check_encode(payload)

def p2pkh_from_pub(pubkey: bytes) -> str:
    h160 = hash160(pubkey)
    # version 0x00 mainnet
    return b58check_encode(b'\x00' + h160)

def p2sh_p2wpkh_from_pub(pubkey: bytes) -> str:
    # redeemScript = 0x00 0x14 <hash160(pubkey)>
    h160 = hash160(pubkey)
    redeem = b'\x00' + b'\x14' + h160
    # P2SH address = base58check(0x05 + HASH160(redeemScript))
    rs_hash160 = hash160(redeem)
    return b58check_encode(b'\x05' + rs_hash160)

def bech32_p2wpkh_from_pub(pubkey: bytes, hrp='bc') -> str:
    h160 = hash160(pubkey)
    return encode_bech32_p2wpkh(h160, hrp=hrp)

def process_one_minikey(mk: str, hrp='bc') -> dict:
    mk = mk.strip()
    if not mk:
        return None
    ok, reason = is_valid_minikey(mk)
    row = {
        "minikey": mk,
        "valid": ok,
        "reason": reason,
        "priv_hex": "",
        "wif_uncompressed": "",
        "wif_compressed": "",
        "addr_p2pkh_uncompressed": "",
        "addr_p2pkh_compressed": "",
        "addr_p2sh_p2wpkh": "",
        "addr_bech32_p2wpkh": ""
    }
    if not ok:
        return row

    priv = minikey_to_privkey(mk)
    # reject invalid zero or >= N just in case (extremely unlikely from SHA256)
    k = int.from_bytes(priv, 'big')
    if k == 0 or k >= SECP256K1_N:
        row["valid"] = False
        row["reason"] = "Privkey tidak valid (0 atau >= n)"
        return row

    row["priv_hex"] = priv.hex()
    # WIFs
    row["wif_uncompressed"] = wif_from_priv(priv, compressed=False)
    row["wif_compressed"]   = wif_from_priv(priv, compressed=True)

    # Pubkeys & addresses
    pub_u = priv_to_pub_uncompressed(priv)
    pub_c = priv_to_pub_compressed(priv)

    row["addr_p2pkh_uncompressed"] = p2pkh_from_pub(pub_u)
    row["addr_p2pkh_compressed"]   = p2pkh_from_pub(pub_c)
    row["addr_p2sh_p2wpkh"]        = p2sh_p2wpkh_from_pub(pub_c)  # nested uses compressed pubkey
    row["addr_bech32_p2wpkh"]      = bech32_p2wpkh_from_pub(pub_c, hrp=hrp)
    return row

def main():
    if len(sys.argv) == 2:
        # Single minikey → print human-readable
        mk = sys.argv[1]
        row = process_one_minikey(mk)
        if row is None:
            print("Input kosong.")
            sys.exit(1)
        print(f"Minikey          : {row['minikey']}")
        print(f"Valid            : {row['valid']} ({row['reason']})")
        if row["valid"]:
            print(f"Priv (hex)       : {row['priv_hex']}")
            print(f"WIF (uncompressed): {row['wif_uncompressed']}")
            print(f"WIF (compressed)  : {row['wif_compressed']}")
            print(f"P2PKH (uncompr.)  : {row['addr_p2pkh_uncompressed']}")
            print(f"P2PKH (compr.)    : {row['addr_p2pkh_compressed']}")
            print(f"P2SH-P2WPKH       : {row['addr_p2sh_p2wpkh']}")
            print(f"Bech32 P2WPKH     : {row['addr_bech32_p2wpkh']}")
        sys.exit(0)

    if len(sys.argv) == 3:
        # File input → CSV output
        in_path = sys.argv[1]
        out_path = sys.argv[2]
        if not os.path.isfile(in_path):
            print(f"File tidak ditemukan: {in_path}")
            sys.exit(1)
        rows = []
        with open(in_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line in f:
                mk = line.strip()
                if not mk:
                    continue
                r = process_one_minikey(mk)
                if r is not None:
                    rows.append(r)

        fieldnames = [
            "minikey","valid","reason","priv_hex",
            "wif_uncompressed","wif_compressed",
            "addr_p2pkh_uncompressed","addr_p2pkh_compressed",
            "addr_p2sh_p2wpkh","addr_bech32_p2wpkh"
        ]
        with open(out_path, 'w', newline='', encoding='utf-8') as csvf:
            w = csv.DictWriter(csvf, fieldnames=fieldnames)
            w.writeheader()
            for r in rows:
                w.writerow(r)
        print(f"Selesai. Tersimpan ke: {out_path}")
        sys.exit(0)

    print("Usage:")
    print("  python minikey_to_addresses.py <MINIKEY>")
    print("  python minikey_to_addresses.py <input.txt> <output.csv>")
    sys.exit(1)

if __name__ == "__main__":
    if _BACKEND is None:
        print("Peringatan: butuh 'ecdsa' atau 'coincurve'. Install salah satu, contoh: pip install ecdsa")
    main()
