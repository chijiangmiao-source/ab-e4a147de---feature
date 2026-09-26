FROM python:3.11-slim

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    HOST=0.0.0.0 \
    PORT=8080

WORKDIR /app

# No third-party dependencies: only the Python standard library is used.
COPY app/ /app/app/
COPY tests/ /app/tests/

# Full build context for the verify service's "image build check" phase:
# when a Docker socket is mounted it can run a real `docker build` against it.
COPY . /src

RUN chmod +x /app/tests/run_verify.sh

EXPOSE 8080

HEALTHCHECK --interval=5s --timeout=3s --start-period=2s --retries=10 \
  CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8080/healthz', timeout=2).status == 200 else 1)"

CMD ["python", "/app/app/server.py"]
