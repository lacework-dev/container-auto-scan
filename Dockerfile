FROM python:3.10-slim

ENV LW_SCANNER_VERSION=0.2.10

RUN apt-get update && apt-get install -y \
    ca-certificates \
    curl \
    gnupg \
    lsb-release \ 
    wget \
    && curl -fsSL https://download.docker.com/linux/debian/gpg | gpg --dearmor -o /usr/share/keyrings/docker-archive-keyring.gpg \
    && echo \
        "deb [arch=$(dpkg --print-architecture) signed-by=/usr/share/keyrings/docker-archive-keyring.gpg] https://download.docker.com/linux/debian \
        $(lsb_release -cs) stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null \ 
    && apt-get update \ 
    && apt-get install docker-ce docker-ce-cli -y \ 
    && rm -rf /var/lib/apt/lists/* \
    && wget https://github.com/lacework/lacework-vulnerability-scanner/releases/download/v${LW_SCANNER_VERSION}/lw-scanner-linux-amd64 \
    && mv lw-scanner-linux-amd64 /usr/local/bin/lw-scanner \
    && chmod +x /usr/local/bin/lw-scanner \
    && apt-get purge curl gnupg lsb-release wget -y

RUN groupadd --gid 5000 user \
    && useradd --home-dir /home/user --create-home --uid 5000 --gid 5000 --shell /bin/sh --skel /dev/null user \
    && usermod -aG docker user \
    && touch /var/run/docker.sock \
    && chown root:docker /var/run/docker.sock

USER user

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /app

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY auto_scan.py ./

ENTRYPOINT [ "python", "-u", "/app/auto_scan.py" ]
