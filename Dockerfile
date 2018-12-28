FROM fedora:29

COPY . /usr/src/bang
WORKDIR /usr/src/bang/src

RUN dnf update -y && \
    dnf install -y python3 \
                   binutils \
                   squashfs-tools \
                   cabextract \
                   p7zip \
                   e2tools \
                   zstd \
                   python3-lz4 \
                   qemu-img \
                   python3-psycopg2 \
                   python3-snappy \
                   python3-tlsh \
                   python3-tinycss2 \
                   python3-dockerfile-parse \
                   openssl \
                   rzip \
                   libxml2 \
                   mailcap \
                   lzop

CMD ["python3","bangshell"]
