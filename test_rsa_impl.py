import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent / "Sha256"))

from rsa_impl import (
    euclidean_extended,
    inverse_mod,
    miller_rabin,
    random_prime,
    build_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    serialize_key,
    deserialize_key,
)


@pytest.fixture(scope="module")
def keys_256():
    """Par de chaves de 256 bits gerado uma única vez por sessão."""
    return build_keypair(bit_length=256)


class TestEuclideanExtended:
    def test_resultado_basico(self):
        div, cx, cy = euclidean_extended(35, 15)
        assert div == 5
        assert 35 * cx + 15 * cy == div

    def test_coprimos(self):
        div, cx, cy = euclidean_extended(17, 13)
        assert div == 1
        assert 17 * cx + 13 * cy == 1

    def test_entrada_zero(self):
        div, cx, cy = euclidean_extended(0, 7)
        assert div == 7


class TestInverseMod:
    def test_valor_conhecido(self):
        assert inverse_mod(3, 5) == 2

    def test_valores_grandes(self):
        a, m = 65537, (2**127 - 1)
        inv = inverse_mod(a, m)
        assert (a * inv) % m == 1

    def test_sem_inverso_lanca_excecao(self):
        with pytest.raises(ValueError):
            inverse_mod(4, 6)


class TestMillerRabin:
    PRIMOS_CONHECIDOS = [2, 3, 5, 7, 11, 13, 97, 101, 7919, 104729]
    COMPOSTOS_CONHECIDOS = [0, 1, 4, 6, 8, 9, 100, 1024, 104728]

    @pytest.mark.parametrize("p", PRIMOS_CONHECIDOS)
    def test_identifica_primos(self, p):
        assert miller_rabin(p), f"{p} deveria ser primo"

    @pytest.mark.parametrize("c", COMPOSTOS_CONHECIDOS)
    def test_identifica_compostos(self, c):
        assert not miller_rabin(c), f"{c} nao deveria ser primo"

    def test_primo_grande(self):
        assert miller_rabin(2**127 - 1)


class TestRandomPrime:
    def test_resultado_e_primo(self):
        p = random_prime(128)
        assert miller_rabin(p)

    def test_comprimento_em_bits(self):
        p = random_prime(128)
        assert p.bit_length() == 128


class TestBuildKeypair:
    def test_retorna_duas_tuplas(self, keys_256):
        pub, priv = keys_256
        assert len(pub) == 2
        assert len(priv) == 2

    def test_modulos_identicos(self, keys_256):
        pub, priv = keys_256
        assert pub[1] == priv[1]

    def test_expoente_publico_padrao(self, keys_256):
        pub, _ = keys_256
        assert pub[0] == 65537

    def test_cifrar_decifrar_identidade(self, keys_256):
        pub, priv = keys_256
        texto = "teste de identidade RSA"
        assert rsa_decrypt(rsa_encrypt(texto, pub), priv) == texto


class TestEncryptDecrypt:
    def test_mensagem_curta(self, keys_256):
        pub, priv = keys_256
        texto = "Ola!"
        assert rsa_decrypt(rsa_encrypt(texto, pub), priv) == texto

    def test_string_vazia(self, keys_256):
        pub, priv = keys_256
        texto = ""
        assert rsa_decrypt(rsa_encrypt(texto, pub), priv) == texto

    def test_unicode(self, keys_256):
        pub, priv = keys_256
        texto = "criptografia: αβγδ — 日本語 🔐"
        assert rsa_decrypt(rsa_encrypt(texto, pub), priv) == texto

    def test_mensagem_longa_varios_blocos(self, keys_256):
        pub, priv = keys_256
        texto = "A" * 500
        blocos = rsa_encrypt(texto, pub)
        assert len(blocos) > 1
        assert rsa_decrypt(blocos, priv) == texto

    def test_chave_errada_lanca_excecao(self, keys_256):
        pub, priv = keys_256
        pub2, priv2 = build_keypair(bit_length=256)
        texto = "segredo"
        blocos = rsa_encrypt(texto, pub)
        with pytest.raises(Exception):
            rsa_decrypt(blocos, priv2)

    def test_cifrado_e_lista_de_inteiros(self, keys_256):
        pub, _ = keys_256
        blocos = rsa_encrypt("hello", pub)
        assert isinstance(blocos, list)
        assert all(isinstance(b, int) for b in blocos)

    def test_cifragem_deterministica(self, keys_256):
        pub, priv = keys_256
        texto = "determinismo"
        assert rsa_encrypt(texto, pub) == rsa_encrypt(texto, pub)

    def test_mensagens_diferentes_cifrados_diferentes(self, keys_256):
        pub, _ = keys_256
        assert rsa_encrypt("mensagem A", pub) != rsa_encrypt("mensagem B", pub)


class TestSignVerify:
    def test_assinatura_valida(self, keys_256):
        pub, priv = keys_256
        texto = "mensagem autenticada"
        sig = rsa_sign(texto, priv)
        assert rsa_verify(texto, sig, pub)

    def test_mensagem_adulterada_falha(self, keys_256):
        pub, priv = keys_256
        texto = "mensagem original"
        sig = rsa_sign(texto, priv)
        assert not rsa_verify(texto + "!", sig, pub)

    def test_chave_errada_falha(self, keys_256):
        pub, priv = keys_256
        pub2, _ = build_keypair(bit_length=256)
        texto = "mensagem"
        sig = rsa_sign(texto, priv)
        assert not rsa_verify(texto, sig, pub2)

    def test_mensagem_vazia(self, keys_256):
        pub, priv = keys_256
        texto = ""
        sig = rsa_sign(texto, priv)
        assert rsa_verify(texto, sig, pub)

    def test_assinatura_e_inteiro(self, keys_256):
        _, priv = keys_256
        sig = rsa_sign("teste", priv)
        assert isinstance(sig, int)


class TestSerialization:
    def test_roundtrip_chave(self, keys_256):
        pub, priv = keys_256
        assert deserialize_key(serialize_key(pub)) == pub
        assert deserialize_key(serialize_key(priv)) == priv

    def test_dict_contem_exp_e_mod(self, keys_256):
        pub, _ = keys_256
        d = serialize_key(pub)
        assert "exp" in d and "mod" in d
