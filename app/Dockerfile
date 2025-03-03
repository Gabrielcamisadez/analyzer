# Imagem base do Python
FROM python:3.9-slim

# Diretório de trabalho
WORKDIR /app

# Copiar os arquivos para o contêiner
COPY . /app

# Instalar dependências
RUN pip install --no-cache-dir -r requirements.txt

# Comando para rodar o app
CMD ["python3", "main.py"]

