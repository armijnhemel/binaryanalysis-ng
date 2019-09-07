# GNU make file

SOURCES = $(shell find parsers -type f -name '*.ksy')
KAITAI_PARSERS = $(patsubst %.ksy, %.py, $(SOURCES))
SPACE:=$(EMPTY) $(EMPTY)
KAITAI_NAMES = $(notdir $(basename $(SOURCES)))
KAITAI_PATTERN = $(subst $(SPACE),\|,$(KAITAI_NAMES))

KAITAISTRUCT_COMPILER= $(HOME)/kaitai-struct-compiler-0.9-SNAPSHOT/bin/kaitai-struct-compiler 

all: $(KAITAI_PARSERS)

%.py : %.ksy
	$(KAITAISTRUCT_COMPILER) -t python --outdir `dirname "$<"` $<
	sed -i 's/^import \($(KAITAI_PATTERN)\)$$/from . &/' "$@"

.PHONY: test parsertests

test:
	python3 -m unittest discover -v -p 'Test*'

parsertests:
	python3 -m unittest discover parsers -v -p 'Test.py'

