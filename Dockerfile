# Clean-environment build: docker build -t bcpsi . && docker run --rm bcpsi
# (use `docker run --rm bcpsi ./run.sh full` for the complete evaluation)
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake git ca-certificates python3 python3-matplotlib \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY . /app
RUN rm -rf build && ./run.sh build
CMD ["./run.sh", "quick"]
