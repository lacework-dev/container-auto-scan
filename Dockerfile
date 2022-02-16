FROM python:3.10-slim

ENV LW_SCANNER_VERSION=0.2.9

RUN groupadd --gid 5000 user && useradd --home-dir /home/user --create-home --uid 5000 --gid 5000 --shell /bin/sh --skel /dev/null user

RUN apt-get update && apt-get install -y \
    wget \
    && rm -rf /var/lib/apt/lists/* \
    && wget https://github.com/lacework/lacework-vulnerability-scanner/releases/download/v${LW_SCANNER_VERSION}/lw-scanner-linux-amd64 \
    && mv lw-scanner-linux-amd64 /usr/local/bin/lw-scanner \
    && chmod +x /usr/local/bin/lw-scanner

USER user

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY auto_scan.py ./

ENTRYPOINT [ "python", "-u", "/app/auto_scan.py" ]
