FROM python:3.12-slim

WORKDIR /app
COPY . /app
RUN python -m pip install --no-cache-dir -e ".[all]"
CMD ["uvicorn", "kaamo.daemon.server:app", "--host", "0.0.0.0", "--port", "8080"]

