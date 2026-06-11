import random
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "Sha256"))
try:
    from sha256_impl import sha256 as _compute_hash
except ImportError:
    import hashlib
    def _compute_hash(data: bytes) -> str:
        return hashlib.sha256(data).hexdigest()


def euclidean_extended(a: int, b: int):
    """Retorna (mdc, coef_a, coef_b) tal que a*coef_a + b*coef_b = mdc."""
    if a == 0:
        return b, 0, 1
    divisor, cx, cy = euclidean_extended(b % a, a)
    return divisor, cy - (b // a) * cx, cx


def inverse_mod(value: int, modulus: int) -> int:
    """Retorna x tal que value*x ≡ 1 (mod modulus)."""
    divisor, coef, _ = euclidean_extended(value % modulus, modulus)
    if divisor != 1:
        raise ValueError(f"Sem inverso modular: mdc({value}, {modulus}) = {divisor}")
    return coef % modulus


def miller_rabin(candidate: int, iterations: int = 20) -> bool:
    """Teste de Miller-Rabin para primalidade probabilística."""
    if candidate < 2:
        return False
    if candidate in (2, 3, 5, 7):
        return True
    if candidate % 2 == 0:
        return False

    exp, odd = 0, candidate - 1
    while odd % 2 == 0:
        exp += 1
        odd //= 2

    for _ in range(iterations):
        base = random.randrange(2, candidate - 2)
        cur = pow(base, odd, candidate)
        if cur in (1, candidate - 1):
            continue
        for _ in range(exp - 1):
            cur = pow(cur, 2, candidate)
            if cur == candidate - 1:
                break
        else:
            return False
    return True


def random_prime(bit_length: int) -> int:
    """Gera primo aleatório com exatamente `bit_length` bits."""
    while True:
        num = random.getrandbits(bit_length)
        num |= (1 << (bit_length - 1)) | 1
        if miller_rabin(num):
            return num


def build_keypair(bit_length: int = 512):
    """Constrói par de chaves RSA (pub, priv) com primos de `bit_length` bits."""
    pub_exp = 65537

    while True:
        prime_p = random_prime(bit_length)
        prime_q = random_prime(bit_length)
        if prime_p == prime_q:
            continue

        modulus = prime_p * prime_q
        totient = (prime_p - 1) * (prime_q - 1)

        if totient % pub_exp == 0:
            continue

        try:
            priv_exp = inverse_mod(pub_exp, totient)
        except ValueError:
            continue

        return (pub_exp, modulus), (priv_exp, modulus)


def _num_to_bytes(n: int) -> bytes:
    byte_len = (n.bit_length() + 7) // 8 or 1
    return n.to_bytes(byte_len, "big")


def _bytes_to_num(b: bytes) -> int:
    return int.from_bytes(b, "big")


def rsa_encrypt(text: str, pub_key: tuple) -> list:
    """Cifra texto em blocos RSA. Retorna lista de inteiros cifrados."""
    exp, mod = pub_key
    mod_bytes = (mod.bit_length() + 7) // 8
    chunk_size = mod_bytes - 2

    payload = text.encode("utf-8")
    if not payload:
        payload = b""

    output = []
    for start in range(0, max(len(payload), 1), chunk_size):
        piece = payload[start : start + chunk_size]
        framed = b"\x01" + piece
        int_val = _bytes_to_num(framed)
        if int_val >= mod:
            raise ValueError("Tamanho do bloco excede o módulo — use chaves maiores.")
        output.append(pow(int_val, exp, mod))
    return output


def rsa_decrypt(cipher_blocks: list, priv_key: tuple) -> str:
    """Decifra lista de blocos RSA em texto."""
    exp, mod = priv_key
    decoded_parts = []
    for block in cipher_blocks:
        int_val = pow(block, exp, mod)
        raw = _num_to_bytes(int_val)
        if raw[:1] != b"\x01":
            raise ValueError("Bloco corrompido ou chave errada.")
        decoded_parts.append(raw[1:])
    return b"".join(decoded_parts).decode("utf-8")


def rsa_sign(text: str, priv_key: tuple) -> int:
    """Gera assinatura RSA-SHA256 de um texto com chave privada."""
    exp, mod = priv_key
    digest = int(_compute_hash(text.encode("utf-8")), 16)
    return pow(digest, exp, mod)


def rsa_verify(text: str, signature: int, pub_key: tuple) -> bool:
    """Confere assinatura RSA-SHA256 com chave pública."""
    exp, mod = pub_key
    expected_digest = int(_compute_hash(text.encode("utf-8")), 16)
    recovered_digest = pow(signature, exp, mod)
    return recovered_digest == expected_digest


def serialize_key(key: tuple) -> dict:
    """Serializa chave (exp, mod) para dicionário compatível com JSON."""
    exp, mod = key
    return {"exp": exp, "mod": mod}


def deserialize_key(data: dict) -> tuple:
    """Reconstrói chave a partir de dicionário."""
    return (int(data["exp"]), int(data["mod"]))


# Aliases para compatibilidade com chat_client.py / test_rsa_impl.py
generate_keypair = build_keypair
encrypt          = rsa_encrypt
decrypt          = rsa_decrypt
sign             = rsa_sign
verify           = rsa_verify
key_to_dict      = serialize_key
key_from_dict    = deserialize_key


def _run_tests():
    """Executa demonstração de cifragem e assinatura RSA."""
    print()

    print("RSA ")
    print()


    print("\nprimeiro:  chaves RSA (numeros primos )...")
    print("          carregando...\n")
    pub, priv = build_keypair(bit_length=512)

    pub_e, pub_n = pub
    priv_d, _ = priv
    print(f"          expoente privado = {str(priv_d)[:40]}...")
    print(f"          modulo           = {str(pub_n)[:40]}...")
    print(f"          expoente publico = {pub_e}")

    test_inputs = [
        "teste1",
        "Opa, teste 2",
        "nada mesmo.",
    ]

    print("\nsegunda parte cifrando e decifrando")
    print()
    all_passed = True
    for entrada in test_inputs:
        blocos = rsa_encrypt(entrada, pub)
        saida = rsa_decrypt(blocos, priv)
        ok = saida == entrada
        if not ok:
            all_passed = False
        etiqueta = repr(entrada) if len(entrada) <= 30 else repr(entrada[:27]) + "..."
        print(f"          [{'fine' if ok else 'bad'}] {etiqueta} => {len(blocos)} bloco(s)")

    sample_msg = "Mensagem autenticada via RSA-SHA256."
    assinatura = rsa_sign(sample_msg, priv)
    check_ok = rsa_verify(sample_msg, assinatura, pub)
    check_tampered = rsa_verify(sample_msg + "!", assinatura, pub)

    print("\nparte 3 Assinatura Digital")
    print()
    print(f"          Texto     : {sample_msg!r}")
    print(f"          Assinatura: {hex(assinatura)[:40]}...")
    print(f"          Verificacao (texto original) : {'OK' if check_ok else 'FALHOU'}")
    print(f"          Verificacao (texto alterado) : {'CORRETO (rejeitado)' if not check_tampered else 'PROBLEMA!'}")

    print()

    status = all_passed and check_ok and not check_tampered
    print("Conclusao:", "Funcionou em todos os casos" if status else "Erro")


if __name__ == "__main__":
    _run_tests()
