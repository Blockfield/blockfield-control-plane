FROM python:3.12-slim@sha256:aa943ce411423c7582288f18707ff66eddcbaeb510502d747a72aeb34f30d159
ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 CP_PORT=8080
WORKDIR /app
COPY requirements.txt ./
RUN pip install --no-cache-dir --require-hashes -r requirements.txt
COPY cpv2 ./cpv2
COPY migrations ./migrations
RUN useradd -r -u 65532 cp
USER cp
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 CMD python3 -c "import os,sys,urllib.request;p=os.environ.get('CP_PORT','8080');sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:'+p+'/health', timeout=4).status == 200 else 1)"
CMD ["python", "-m", "cpv2"]
