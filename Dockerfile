FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CP_DB=/data/cp.sqlite CP_PORT=8080
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY api.py ./
COPY cpv2 ./cpv2
COPY migrations ./migrations
RUN useradd -r -u 65532 cp && mkdir -p /data && chown cp:cp /data
USER cp
VOLUME /data
EXPOSE 8080
CMD ["python3", "api.py"]
