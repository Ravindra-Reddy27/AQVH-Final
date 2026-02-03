FROM python:3.10-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# FIX: Added --timeout 600 to allow waiting for Quantum queues
CMD ["gunicorn", "-b", "0.0.0.0:8000", "--timeout", "600", "app:app"]