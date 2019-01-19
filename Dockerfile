FROM fedora:29

COPY . /usr/src/bang
WORKDIR /usr/src/bang/src

RUN dnf update -y && \
    dnf install -y binutils \
                   cabextract \
                   e2tools \
                   libxml2 \
                   lzop \
                   mailcap \
                   openssl \
                   p7zip \
                   python3 \
                   python3-dockerfile-parse \
                   python3-lz4 \
                   python3-pillow \
                   python3-psycopg2 \
                   python3-snappy \
                   python3-tinycss2 \
                   python3-tlsh \
                   qemu-img \
                   rzip \
                   squashfs-tools \
                   zstd \
                   python3-defusedxml \
                   java-1.8.0-openjdk-headless

CMD ["python3","bangshell"]
