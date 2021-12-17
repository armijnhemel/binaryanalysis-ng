INPUTDIR = ${shell pwd}/../testfiles/
INPUTFILE = openwrt/openwrt-21.02.1-x86-generic-generic-squashfs-combined-efi.img.gz
INPUTPATH = ${INPUTDIR}${INPUTFILE}
OUTPUT = ../testfiles/unpack
SRC = ${shell pwd}/src
RESULTS = bang-scan-grgcj2k2

PODMANCMD = sudo podman container run -it --rm -v "${OUTPUT}":/unpack -v "${INPUTDIR}":/input -v "${SRC}":/src:z -v /tmp:/tmp:z -w /src bang 

all: base-images bang-container unpack

base-images:
	cd util; sudo make all

bang-container: base-images
	cd src; sudo make ctrbuild

unpack:
	${PODMANCMD} python3 /src/bang-scanner -c bang.config -f /input/${INPUTFILE}

bash:
	${PODMANCMD} bash

cve: 
	${PODMANCMD} python3 /src/cve/cve_finder.py -c /src/cve/cve-config.yaml -r /unpack/${RESULTS}
