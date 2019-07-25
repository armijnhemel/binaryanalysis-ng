# GNU make file

SOURCES = $(shell find . -type f -name '*.ksy')
KAITAI_PARSERS = $(patsubst %.ksy, %.py, $(SOURCES))

KAITAISTRUCT_COMPILER= $(HOME)/kaitai-struct-compiler-0.9-SNAPSHOT/bin/kaitai-struct-compiler 

all: $(KAITAI_PARSERS)

%.py : %.ksy
	$(KAITAISTRUCT_COMPILER) -t python --outdir `dirname "$<"` $<

