FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && useradd --create-home app && mkdir /data && chown app /data
USER app
ENV PORT=8000 DATA_DIR=/data
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['PORT']+'/healthz')"
CMD ["sh", "-c", "vibe-lube-web --host 0.0.0.0 --port $PORT --data-dir $DATA_DIR"]
