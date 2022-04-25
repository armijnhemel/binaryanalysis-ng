FROM kaitai as builder
RUN apt-get update && apt-get install make

COPY . /usr/src/bang/src
WORKDIR /usr/src/bang/src
ENV PATH="${PATH}:/kaitai-struct-compiler/bin"

RUN make

FROM fedora:33


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
                   lzo-devel \
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

COPY --from=builder /kaitai_struct /kaitai_struct
WORKDIR /kaitai_struct/runtime/python
RUN python3 setup.py install


CMD ["python3","bangshell"]
