import sys
import threading
from datetime import datetime
from flask import Flask, request, jsonify

srv = Flask(__name__)

_mutex = threading.Lock()
_registry: dict[str, dict] = {}
_inbox: dict[str, list] = {}


def _log(entry):
    """Grava mensagem no stderr."""
    sys.stderr.write(entry + "\n")
    sys.stderr.flush()


@srv.route("/register", methods=["POST"])
def handle_register():
    """Cadastra um novo participante com sua chave pública RSA."""
    body = request.get_json(silent=True) or {}
    name = (body.get("username") or "").strip()
    pub_key = body.get("public_key")

    if not name:
        return jsonify({"error": "campo 'username' é obrigatório"}), 400
    if not pub_key or "exp" not in pub_key or "mod" not in pub_key:
        return jsonify({"error": "campo 'public_key' deve conter 'exp' e 'mod'"}), 400

    with _mutex:
        _registry[name] = pub_key
        _inbox.setdefault(name, [])

    _log(f"[CADASTRO] {name} entrou.")
    return jsonify({"status": "ok", "username": name})


@srv.route("/keys/<username>", methods=["GET"])
def handle_get_key(username):
    """Retorna a chave pública de um participante."""
    with _mutex:
        if username not in _registry:
            return jsonify({"error": f"participante '{username}' não encontrado"}), 404
        return jsonify({"username": username, "public_key": _registry[username]})


@srv.route("/users", methods=["GET"])
def handle_list_users():
    """Lista todos os participantes cadastrados."""
    with _mutex:
        return jsonify({"users": list(_registry.keys())})


@srv.route("/webhook/message", methods=["POST"])
def handle_incoming_message():
    """Recebe mensagem cifrada e encaminha ao destinatário."""
    body = request.get_json(silent=True) or {}
    origin    = (body.get("from") or "").strip()
    target    = (body.get("to")   or "").strip()
    blocks    = body.get("blocks")
    signature = body.get("signature")

    if not origin or not target:
        return jsonify({"error": "campos 'from' e 'to' são obrigatórios"}), 400
    if not isinstance(blocks, list) or not blocks:
        return jsonify({"error": "campo 'blocks' deve ser lista não-vazia"}), 400
    if signature is None:
        return jsonify({"error": "campo 'signature' é obrigatório"}), 400

    with _mutex:
        if origin not in _registry:
            return jsonify({"error": f"remetente '{origin}' não cadastrado"}), 404
        if target not in _registry:
            return jsonify({"error": f"destinatário '{target}' não cadastrado"}), 404

        _inbox[target].append({
            "from":      origin,
            "blocks":    blocks,
            "signature": signature,
            "timestamp": datetime.now().isoformat(timespec="seconds"),
        })

    _log(f"[MENSAGEM] {origin} -> {target} ({len(blocks)} bloco(s))")
    return jsonify({"status": "entregue", "to": target})


@srv.route("/messages/<username>", methods=["GET"])
def handle_fetch_messages(username):
    """Retorna e esvazia a caixa de entrada do participante."""
    with _mutex:
        if username not in _registry:
            return jsonify({"error": f"participante '{username}' não cadastrado"}), 404
        pending = _inbox.get(username, [])
        _inbox[username] = []
    return jsonify({"messages": pending})


@srv.route("/status", methods=["GET"])
def handle_status():
    """Retorna informações de estado do servidor."""
    with _mutex:
        return jsonify({
            "status": "online",
            "participantes": len(_registry),
            "msgs_aguardando": sum(len(v) for v in _inbox.values()),
        })


if __name__ == "__main__":
    print("=" * 55)
    print("Chat E2E RSA -- Servidor de Mensagens")
    print("=" * 55)
    print("Porta     : 5000")
    print("URL base  : http://localhost:5000")
    print("Aguardando conexoes dos clientes...")
    print("=" * 55)
    srv.run(host="0.0.0.0", port=5000, debug=False)
