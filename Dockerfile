FROM python:3.10-slim

RUN groupadd --gid 5000 user && useradd --home-dir /home/user --create-home --uid 5000 --gid 5000 --shell /bin/sh --skel /dev/null user
USER user

ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

WORKDIR /app

RUN mkdir cache

COPY requirements.txt ./
RUN pip install -r requirements.txt

COPY utils/*.py utils/
COPY auto_scan.py ./

ENTRYPOINT [ "python", "-u", "/app/auto_scan.py" ]
