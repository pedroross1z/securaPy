FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# o modelo e treinado DENTRO da imagem (mesmas versoes de sklearn/joblib que vao rodar) e o hash
# SHA-256 e gravado junto; em runtime o modelo so e carregado se o hash conferir
RUN python -m ml.treinar

# usuario sem privilegios (nao roda como root)
RUN useradd --create-home --uid 10001 securapy && mkdir -p /app/saida && chown -R securapy /app/saida
USER securapy

EXPOSE 5000 9999
HEALTHCHECK --interval=15s --timeout=5s --start-period=40s --retries=5 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:5000/api/health', timeout=4).status == 200 else 1)"

# 1 worker + threads: o servidor de alertas em tempo real (socket) vive dentro do processo da API
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "1", "--threads", "8", "--timeout", "60", "wsgi:app"]
