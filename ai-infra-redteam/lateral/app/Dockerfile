# Small RAG app used as the attacker's assumed foothold container for the
# lateral-movement test. Not hardened on purpose in either direction: this
# is a plain, unremarkable app image, which is the realistic case.
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY rag_app.py .

CMD ["uvicorn", "rag_app:app", "--host", "0.0.0.0", "--port", "9000"]
