FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN mkdir -p data/rules data/gitleaks data/osv \
    data/feedback reports test_results

EXPOSE 8000

# Let the platform provide PORT (Render, etc.); default to 8000 locally
ENV PORT=8000

CMD ["sh", "-c", "uvicorn api.main:app --host 0.0.0.0 --port ${PORT}"]