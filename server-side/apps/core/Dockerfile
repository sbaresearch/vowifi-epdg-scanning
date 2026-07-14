FROM golang:1.25 AS builder

WORKDIR /tmp/zdns

# install git.
RUN apt-get update && apt-get install -y git

ENV GOBIN=/usr/local/bin

# clone and build zdns.
RUN git clone https://github.com/zmap/zdns.git . \
    && make install

FROM python:3.12-slim

WORKDIR /app

COPY --from=builder /usr/local/bin/zdns /usr/local/bin/zdns

# install tcpdump and python runtime tools
RUN apt-get update && apt-get install -y \
        python3 \
        python3-pip \
        tcpdump

# pg_dump for the SQL takeout. postgres version pinned.
RUN apt-get update \
    && apt-get install -y --no-install-recommends curl ca-certificates gnupg \
    && install -d /usr/share/postgresql-common/pgdg \
    && curl -fsSL https://www.postgresql.org/media/keys/ACCC4CF8.asc \
        -o /usr/share/postgresql-common/pgdg/apt.postgresql.org.asc \
    && echo "deb [signed-by=/usr/share/postgresql-common/pgdg/apt.postgresql.org.asc] https://apt.postgresql.org/pub/repos/apt $(. /etc/os-release && echo $VERSION_CODENAME)-pgdg main" \
        > /etc/apt/sources.list.d/pgdg.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends postgresql-client-18 \
    && apt-get purge -y --auto-remove curl gnupg \
    && rm -rf /var/lib/apt/lists/*

# install requirements.
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

# copy scanner package
COPY scanner /app/scanner

# default run command
CMD ["python3", "-u", "-m", "scanner.main"]
