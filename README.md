# Chat E2E RSA

Chat de terminal com criptografia ponta a ponta usando RSA e SHA256.

---

## Estrutura de pastas

```
seu_projeto/
├── RSA/
│   ├── rsa_impl.py
│   └── test_rsa_impl.py
├── Sha256/
│   └── sha256_impl.py
├── chat_server.py
└── chat_client.py
```

---

## Instalando dependências

```bash
pip install flask requests pytest
```

---

## Rodando o chat

Você precisa de **3 terminais abertos**.

**Terminal 1 — servidor:**
```bash
python chat_server.py
```

**Terminal 2 — primeiro usuário:**
```bash
python chat_client.py alice
```

**Terminal 3 — segundo usuário:**
```bash
python chat_client.py bob
```

Para enviar uma mensagem, digite no terminal do remetente:
```
[alice] bob: oi bob!
```

Para listar usuários conectados:
```
[alice] /usuarios
```

Para sair:
```
[alice] /sair
```

---

## Rodando os testes

```bash
cd RSA
python -m pytest test_rsa_impl.py -v
```

Resultado esperado: **47 passed**
