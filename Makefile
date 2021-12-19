INPUTDIR = ${shell pwd}/../testfiles/
INPUTFILE = openwrt/unpacked.gpt-partition1.part
INPUTPATH = ${INPUTDIR}${INPUTFILE}
OUTPUT = ${shell pwd}/../testfiles/unpack
SRC = ${shell pwd}/src
RESULTS = bang-scan-grgcj2k2

PODMANCMD = sudo docker run -it --rm -v "${OUTPUT}":/unpack -v "${INPUTDIR}":/input -v "${SRC}":/src:z -v /tmp:/tmp:z -u 0 -w /src bang 

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
	last_result=$(shell ${PODMANCMD} ls -Art1 /unpack | tail -n 1); \
	${PODMANCMD} python3 /src/cve/cve_finder.py -c /src/cve/cve-config.yaml -r /unpack/$$last_result
