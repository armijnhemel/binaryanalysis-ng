# GNU make file

SOURCES = $(shell find parsers -type f -name '*.ksy')
KAITAI_PARSERS = $(patsubst %.ksy, %.py, $(SOURCES))
SPACE:=$(EMPTY) $(EMPTY)
KAITAI_NAMES = $(notdir $(basename $(SOURCES)))
KAITAI_PATTERN = $(subst $(SPACE),\|,$(KAITAI_NAMES))

# Assume kaitai-struct-compiler is in $PATH
ifdef DOCKER
KAITAISTRUCT_COMPILER= docker container run -it --rm -v "$(PWD)":/src:z -w /src blacktop/kaitai
else
KAITAISTRUCT_COMPILER= kaitai-struct-compiler 
endif

all: $(KAITAI_PARSERS)

%.py : %.ksy
	$(KAITAISTRUCT_COMPILER) -t python --outdir `dirname "$<"` $<
	sed -i 's/^from \($(KAITAI_PATTERN)\) import /from .\1 import /' "$@"
	sed -i 's/^import \($(KAITAI_PATTERN)\)$$/from . &/' "$@"

.PHONY: test parsertests clean

ifdef DOCKER
PYTEST=docker container run -it --rm -v "$(PWD)":/src:z -w /src bang py.test
else
PYTEST=py.test
endif

test:
	# python3 -m unittest discover -v -p 'Test*'
	$(PYTEST)

parsertests:
	# python3 -m unittest discover parsers -v -p 'Test.py'
	$(PYTEST)

clean:
	rm $(KAITAI_PARSERS)

