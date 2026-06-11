"""Terminal de chat com criptografia ponta a ponta via RSA e SHA256 puros."""

import sys
import threading
from pathlib import Path

_BASE = Path(__file__).resolve().parent
sys.path.insert(0, str(_BASE.parent / "RSA"))
sys.path.insert(0, str(_BASE.parent / "Sha256"))

from rsa_impl import (
    build_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_sign,
    rsa_verify,
    serialize_key,
    deserialize_key,
)

try:
    import requests
except ImportError:
    print("ERRO: biblioteca 'requests' nao encontrada. Instale com: pip install requests")
    sys.exit(1)

BASE_URL = "http://localhost:5000"
CHECK_INTERVAL = 2


def _http_post(endpoint: str, data: dict) -> dict:
    resp = requests.post(f"{BASE_URL}{endpoint}", json=data, timeout=5)
    resp.raise_for_status()
    return resp.json()


def _http_get(endpoint: str) -> dict:
    resp = requests.get(f"{BASE_URL}{endpoint}", timeout=5)
    resp.raise_for_status()
    return resp.json()


def register_user(name: str, pub_key: tuple):
    """Cadastra o participante e sua chave pública no servidor."""
    return _http_post("/register", {
        "username":   name,
        "public_key": serialize_key(pub_key),
    })


def fetch_pubkey(name: str) -> tuple:
    """Obtém a chave pública de outro participante."""
    result = _http_get(f"/keys/{name}")
    return deserialize_key(result["public_key"])


def dispatch_message(sender: str, recipient: str, content: str,
                     dest_pub: tuple, origin_priv: tuple):
    """Cifra e envia mensagem ao destinatário, assinada com chave privada."""
    cipher_blocks = rsa_encrypt(content, dest_pub)
    msg_signature = rsa_sign(content, origin_priv)
    return _http_post("/webhook/message", {
        "from":      sender,
        "to":        recipient,
        "blocks":    cipher_blocks,
        "signature": msg_signature,
    })


def pull_messages(name: str) -> list:
    """Busca e remove mensagens pendentes do servidor."""
    return _http_get(f"/messages/{name}").get("messages", [])


def get_online_users() -> list:
    """Retorna lista de participantes cadastrados."""
    return _http_get("/users").get("users", [])


def _inbox_watcher(name: str, priv_key: tuple, halt: threading.Event):
    """Loop de verificação de mensagens a cada 2 segundos."""
    while not halt.is_set():
        try:
            pending = pull_messages(name)
            for item in pending:
                origin    = item["from"]
                blocks    = item["blocks"]
                signature = item["signature"]
                when      = item.get("timestamp", "")

                try:
                    content    = rsa_decrypt(blocks, priv_key)
                    origin_pub = fetch_pubkey(origin)
                    is_valid   = rsa_verify(content, signature, origin_pub)
                    tag        = "[assinatura valida]" if is_valid else "[ASSINATURA INVALIDA!]"
                    print(f"\n  {when} | {origin}: {content}  {tag}")
                except Exception as err:
                    print(f"\n  [FALHA ao processar mensagem de {origin}]: {err}")

                print(f"[{name}] ", end="", flush=True)
        except Exception:
            pass
        halt.wait(CHECK_INTERVAL)


def main():
    print("#" * 60)
    print("Terminal de Chat com Criptografia RSA Ponta a Ponta")
    print("Algoritmos: RSA + SHA256 (implementacao propria)")
    print("#" * 60)

    if len(sys.argv) > 1:
        name = sys.argv[1].strip()
        print(f"Participante: {name}")
    else:
        name = input("Informe seu nome de usuario: ").strip()
    if not name:
        print("Nome invalido.")
        sys.exit(1)

    print(f"\nGerando chaves RSA 512 bits para '{name}'...")
    print("Aguarde alguns instantes...\n")
    pub_key, priv_key = build_keypair(bit_length=512)
    pub_e, pub_n = pub_key
    print(f"  Chave publica: e={pub_e}, n={str(pub_n)[:30]}...")

    try:
        register_user(name, pub_key)
        print(f"  Participante '{name}' registrado com sucesso.\n")
    except requests.exceptions.ConnectionError:
        print("\nERRO: Nao foi possivel conectar em http://localhost:5000")
        print("      Inicie o servidor primeiro com:  python chat_server.py")
        sys.exit(1)
    except Exception as err:
        print(f"\nERRO no cadastro: {err}")
        sys.exit(1)

    halt_event = threading.Event()
    watcher = threading.Thread(
        target=_inbox_watcher,
        args=(name, priv_key, halt_event),
        daemon=True,
    )
    watcher.start()

    print("Comandos:")
    print("  <destinatario>: <mensagem>  -- envia mensagem cifrada")
    print("  /usuarios                   -- lista participantes")
    print("  /sair                       -- encerra o chat")
    print()

    try:
        while True:
            try:
                line = input(f"[{name}] ")
            except (EOFError, KeyboardInterrupt):
                break

            line = line.strip()
            if not line:
                continue

            if line == "/sair":
                break

            if line == "/usuarios":
                try:
                    users = get_online_users()
                    print(f"  Participantes: {', '.join(users) or '(nenhum)'}")
                except Exception as err:
                    print(f"  Erro: {err}")
                continue

            if ":" not in line:
                print("  Use o formato: <destinatario>: <mensagem>")
                continue

            dest, _, body = line.partition(":")
            dest = dest.strip()
            body = body.strip()

            if not dest or not body:
                print("  Destinatario ou conteudo da mensagem esta vazio.")
                continue

            try:
                dest_pub = fetch_pubkey(dest)
                dispatch_message(name, dest, body, dest_pub, priv_key)
                print(f"  Enviou para o(a) '{dest}' ")
            except requests.exceptions.HTTPError as err:
                print(f"  Erro HTTP: {err.response.json().get('error', err)}")
            except Exception as err:
                print(f"  Falha: {err}")

    finally:
        halt_event.set()
        print("\nEncerrando sessao.")


if __name__ == "__main__":
    main()
