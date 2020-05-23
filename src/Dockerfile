FROM blacktop/kaitai as builder
RUN apt-get update && apt-get install make

COPY . /usr/src/bang/src
WORKDIR /usr/src/bang/src
RUN make

FROM fedora:29

RUN dnf update -y && \
    dnf install -y binutils \
                   cabextract \
                   cpio \
                   e2tools \
                   java-1.8.0-openjdk-headless \
                   libxml2 \
                   lz4 \
                   lzop \
                   mailcap \
                   ncompress \
                   openssl \
                   p7zip \
                   p7zip-plugins \
                   python3 \
                   python3-defusedxml \
                   python3-dockerfile-parse \
                   python3-elasticsearch \
                   python3-icalendar \
                   python3-lz4 \
                   python3-pillow \
                   python3-psycopg2 \
                   python3-snappy \
                   python3-tinycss2 \
                   python3-tlsh \
                   qemu-img \
                   rzip \
                   squashfs-tools \
                   util-linux \
                   zstd

RUN dnf install -y python3-pip
COPY --from=builder /usr/src/bang /usr/src/bang
WORKDIR /usr/src/bang/src
# RUN pip3 install deepdiff
RUN pip3 install -r requirements.txt

CMD ["python3","bangshell"]
