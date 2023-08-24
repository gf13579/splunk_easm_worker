# Build
FROM golang:1.20.4-alpine AS builder
RUN apk add --no-cache git build-base gcc musl-dev
WORKDIR /app
ENV CGO_ENABLED=0
RUN git clone https://github.com/projectdiscovery/httpx.git
RUN git clone https://github.com/projectdiscovery/subfinder.git
RUN git clone https://github.com/projectdiscovery/dnsx.git
RUN git clone https://github.com/projectdiscovery/uncover.git
# RUN git clone https://github.com/projectdiscovery/katana.git
RUN wget https://github.com/projectdiscovery/katana/releases/download/v1.0.3/katana_1.0.3_linux_amd64.zip && unzip katana_1.0.3_linux_amd64.zip

# subfinder
WORKDIR /app/subfinder/v2
RUN go mod download
RUN go build ./cmd/subfinder

# httpx
WORKDIR /app/httpx
RUN go mod download
RUN go build ./cmd/httpx

# dnsx
WORKDIR /app/dnsx
RUN go mod download
RUN go build ./cmd/dnsx

# uncover
WORKDIR /app/uncover
RUN go mod download
RUN go build ./cmd/uncover

# 2023-08-20: Commented-out as this is currently broken
# Instead, we just wget a specific recent release of katana
# katana
# WORKDIR /app/katana
# RUN go mod download
# RUN go build ./cmd/katana

WORKDIR /app/

# release
# FROM python:3.10.12-alpine
# FROM alpine:latest
FROM python:3.11.3
EXPOSE 8000
RUN apt-get update
RUN wget https://dl.google.com/linux/direct/google-chrome-stable_current_amd64.deb
RUN apt install -f -y ./google-chrome-stable_current_amd64.deb
COPY --from=builder /app/httpx/httpx /usr/local/bin/
COPY --from=builder /app/subfinder/v2/subfinder /usr/local/bin/
COPY --from=builder /app/dnsx/dnsx /usr/local/bin/
COPY --from=builder /app/uncover/uncover /usr/local/bin/
COPY --from=builder /app/katana /usr/local/bin/
COPY ./subfinder-provider-config.yaml /root/.config/subfinder/provider-config.yaml

WORKDIR /code
COPY ./requirements.txt /code/requirements.txt
RUN pip install --no-cache-dir --upgrade -r /code/requirements.txt
COPY ./ /code/api
CMD ["uvicorn", "api.__main__:app", "--host", "0.0.0.0", "--port", "80"]