"""Exercicio 13.1 - Chatbot de seguranca com historico de conversa.

O historico e a lista `messages` que cresce a cada turno (system + user/assistant
alternados); e ela que da "memoria" ao modelo - a API em si nao guarda estado.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from llm_comum import MODELO, SYSTEM_CHAT, obter_cliente  # noqa: E402

MAX_MENSAGENS = 20      # janela do historico: controla custo (tokens) e vazamento de contexto


class Chatbot:
    def __init__(self, client):
        self.client = client
        self.mensagens = [{"role": "system", "content": SYSTEM_CHAT}]

    def _aparar(self):
        if len(self.mensagens) > MAX_MENSAGENS + 1:
            self.mensagens = self.mensagens[:1] + self.mensagens[-MAX_MENSAGENS:]

    def perguntar(self, texto):
        self.mensagens.append({"role": "user", "content": texto})
        try:
            r = self.client.chat.completions.create(model=MODELO, messages=self.mensagens,
                                                    temperature=0.3)
            resposta = r.choices[0].message.content
        except Exception as e:
            self.mensagens.pop()                       # nao deixa pergunta sem resposta no historico
            nome = type(e).__name__
            dica = {"AuthenticationError": "verifique OPENAI_API_KEY",
                    "RateLimitError": "limite/crédito excedido, tente depois",
                    "APIConnectionError": "sem conexão com a API",
                    "APITimeoutError": "tempo esgotado"}.get(nome, "tente novamente")
            return f"[erro da API: {nome} — {dica}]"
        self.mensagens.append({"role": "assistant", "content": resposta})
        self._aparar()
        return resposta


def main():
    client, mock = obter_cliente()
    if mock:
        print("[aviso] OPENAI_API_KEY não definida — usando modelo simulado (mock).")
    bot = Chatbot(client)
    print("Chatbot de segurança. Digite /sair para encerrar.")
    while True:
        try:
            texto = input("Você: ").strip()
        except (EOFError, KeyboardInterrupt):
            texto = "/sair"
        if not texto:
            continue
        if texto.lower() == "/sair":
            print("Assistente: Até logo!")
            break
        print(f"Assistente: {bot.perguntar(texto[:2000])}")


if __name__ == "__main__":
    main()
