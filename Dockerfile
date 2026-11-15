FROM python:3.12-slim
WORKDIR /app
COPY . /app
RUN pip install --no-cache-dir . && useradd --create-home app && mkdir /data && chown app /data
ENV PORT=8000 DATA_DIR=/data
EXPOSE 8000
HEALTHCHECK CMD python -c "import urllib.request,os;urllib.request.urlopen('http://127.0.0.1:'+os.environ['PORT']+'/healthz')"
# Hosts mount the data disk owned by root. Take ownership, then drop to the unprivileged user;
# if the platform already runs us unprivileged, start directly.
CMD ["sh", "-c", "if [ $(id -u) = 0 ]; then chown -R app:app $DATA_DIR && exec setpriv --reuid=app --regid=app --init-groups vibe-lube-web --host 0.0.0.0 --port $PORT --data-dir $DATA_DIR; else exec vibe-lube-web --host 0.0.0.0 --port $PORT --data-dir $DATA_DIR; fi"]
