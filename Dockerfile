FROM python:3.13-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Default command runs the monitoring loop.
# Override with `dashboard.py` (see docker-compose.yml) to run the web UI.
CMD ["python", "main.py"]
