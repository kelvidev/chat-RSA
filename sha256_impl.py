import struct
from typing import List


INIT_HASH = [
    0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
    0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
]

ROUND_CONSTANTS = [
    0x428A2F98, 0x71374491, 0xB5C0FBCF, 0xE9B5DBA5,
    0x3956C25B, 0x59F111F1, 0x923F82A4, 0xAB1C5ED5,
    0xD807AA98, 0x12835B01, 0x243185BE, 0x550C7DC3,
    0x72BE5D74, 0x80DEB1FE, 0x9BDC06A7, 0xC19BF174,
    0xE49B69C1, 0xEFBE4786, 0x0FC19DC6, 0x240CA1CC,
    0x2DE92C6F, 0x4A7484AA, 0x5CB0A9DC, 0x76F988DA,
    0x983E5152, 0xA831C66D, 0xB00327C8, 0xBF597FC7,
    0xC6E00BF3, 0xD5A79147, 0x06CA6351, 0x14292967,
    0x27B70A85, 0x2E1B2138, 0x4D2C6DFC, 0x53380D13,
    0x650A7354, 0x766A0ABB, 0x81C2C92E, 0x92722C85,
    0xA2BFE8A1, 0xA81A664B, 0xC24B8B70, 0xC76C51A3,
    0xD192E819, 0xD6990624, 0xF40E3585, 0x106AA070,
    0x19A4C116, 0x1E376C08, 0x2748774C, 0x34B0BCB5,
    0x391C0CB3, 0x4ED8AA4A, 0x5B9CCA4F, 0x682E6FF3,
    0x748F82EE, 0x78A5636F, 0x84C87814, 0x8CC70208,
    0x90BEFFFA, 0xA4506CEB, 0xBEF9A3F7, 0xC67178F2,
]

WORD_MASK = 0xFFFFFFFF


def rotate_right(val: int, amount: int) -> int:
    """Rotação circular à direita em 32 bits."""
    return ((val >> amount) | (val << (32 - amount))) & WORD_MASK


def shift_right(val: int, amount: int) -> int:
    """Deslocamento lógico à direita."""
    return (val >> amount) & WORD_MASK


def choice(x: int, y: int, z: int) -> int:
    """Função de escolha: (x AND y) XOR (NOT x AND z)."""
    return (x & y) ^ (~x & z) & WORD_MASK


def majority(x: int, y: int, z: int) -> int:
    """Função de maioria: (x AND y) XOR (x AND z) XOR (y AND z)."""
    return (x & y) ^ (x & z) ^ (y & z)


def upper_sigma0(x: int) -> int:
    """Sigma0 superior: ROTR²(x) XOR ROTR¹³(x) XOR ROTR²²(x)."""
    return rotate_right(x, 2) ^ rotate_right(x, 13) ^ rotate_right(x, 22)


def upper_sigma1(x: int) -> int:
    """Sigma1 superior: ROTR⁶(x) XOR ROTR¹¹(x) XOR ROTR²⁵(x)."""
    return rotate_right(x, 6) ^ rotate_right(x, 11) ^ rotate_right(x, 25)


def lower_sigma0(x: int) -> int:
    """Sigma0 inferior: ROTR⁷(x) XOR ROTR¹⁸(x) XOR SHR³(x)."""
    return rotate_right(x, 7) ^ rotate_right(x, 18) ^ shift_right(x, 3)


def lower_sigma1(x: int) -> int:
    """Sigma1 inferior: ROTR¹⁷(x) XOR ROTR¹⁹(x) XOR SHR¹⁰(x)."""
    return rotate_right(x, 17) ^ rotate_right(x, 19) ^ shift_right(x, 10)


def apply_padding(data: bytes) -> bytes:
    """Aplica padding SHA-256: bit 1, zeros e tamanho em 64 bits big-endian."""
    total_bits = len(data) * 8
    data += b"\x80"
    while (len(data) % 64) != 56:
        data += b"\x00"
    data += struct.pack(">Q", total_bits)
    return data


def sha256(data: bytes) -> str:
    """Calcula SHA-256 de bytes de entrada. Retorna digest hexadecimal de 64 chars."""
    padded_data = apply_padding(data)

    s0, s1, s2, s3, s4, s5, s6, s7 = INIT_HASH[:]

    for offset in range(0, len(padded_data), 64):
        chunk = padded_data[offset : offset + 64]

        schedule: List[int] = list(struct.unpack(">16I", chunk))
        for idx in range(16, 64):
            word = (lower_sigma1(schedule[idx - 2]) + schedule[idx - 7] + lower_sigma0(schedule[idx - 15]) + schedule[idx - 16]) & WORD_MASK
            schedule.append(word)

        va, vb, vc, vd, ve, vf, vg, vh = s0, s1, s2, s3, s4, s5, s6, s7

        for round_idx in range(64):
            temp1 = (vh + upper_sigma1(ve) + choice(ve, vf, vg) + ROUND_CONSTANTS[round_idx] + schedule[round_idx]) & WORD_MASK
            temp2 = (upper_sigma0(va) + majority(va, vb, vc)) & WORD_MASK
            vh = vg
            vg = vf
            vf = ve
            ve = (vd + temp1) & WORD_MASK
            vd = vc
            vc = vb
            vb = va
            va = (temp1 + temp2) & WORD_MASK

        s0 = (s0 + va) & WORD_MASK
        s1 = (s1 + vb) & WORD_MASK
        s2 = (s2 + vc) & WORD_MASK
        s3 = (s3 + vd) & WORD_MASK
        s4 = (s4 + ve) & WORD_MASK
        s5 = (s5 + vf) & WORD_MASK
        s6 = (s6 + vg) & WORD_MASK
        s7 = (s7 + vh) & WORD_MASK

    raw_digest = struct.pack(">8I", s0, s1, s2, s3, s4, s5, s6, s7)
    return raw_digest.hex()


def sha256_file(path: str) -> str:
    """Calcula SHA-256 de um arquivo em disco."""
    with open(path, "rb") as fp:
        content = fp.read()
    return sha256(content)


def _run_demo():
    """Testa a implementação contra vetores de referência NIST."""
    import hashlib

    vectors = [
        b"",
        b"Abacate do mau",
        b"nothing at all",
    ]

    print("*" * 64)
    print("SHA-256 ")
    print("*" * 64)

    passed_all = True
    for entrada in vectors:
        referencia = hashlib.sha256(entrada).hexdigest()
        resultado = sha256(entrada)
        ok = resultado == referencia
        if not ok:
            passed_all = False
        rotulo = repr(entrada) if len(entrada) <= 8 else repr(entrada[:8]) + "..."
        status = "fine" if ok else "bad"
        print(f"  [{status}] {rotulo}")
        print(f"         original: {referencia}")
        print(f"         final : {resultado}")

    print("*" * 64)
    print("Status final:", "TUDO CORRETO" if passed_all else "FALHAS DETECTADAS")


if __name__ == "__main__":
    _run_demo()
