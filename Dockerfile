FROM python:3.12-slim

WORKDIR /app

# Copy requirements first for caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

EXPOSE 8080  # Fly.io often uses 8080; matches PORT env

CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]
