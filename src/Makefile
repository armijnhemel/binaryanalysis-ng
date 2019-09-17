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

coverage:
	coverage3 run --omit "*/__init__.py","*/site-packages/*","test/*.py","parsers/*/Test.py" -m unittest discover -v -p 'Test*.py' || true
	coverage3 html -d test/coverage
	@echo Coverage report available in test/coverage/index.html
