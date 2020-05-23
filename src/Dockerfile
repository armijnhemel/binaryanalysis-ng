FROM blacktop/kaitai as builder
RUN apt-get update && apt-get install make

COPY . /usr/src/bang/src
WORKDIR /usr/src/bang/src
RUN make

FROM fedora:29

RUN dnf update -y
RUN dnf install -y binutils \
                   cabextract \
                   cpio \
                   e2tools \
                   gcc \
                   gcc-c++ \
                   redhat-rpm-config \
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
                   python3-devel \
                   qemu-img \
                   rzip \
                   snappy-devel \
                   squashfs-tools \
                   util-linux \
                   zstd

RUN dnf install -y python3-pip
COPY --from=builder /usr/src/bang /usr/src/bang
WORKDIR /usr/src/bang/src
RUN pip3 install -r requirements.txt

CMD ["python3","bangshell"]
