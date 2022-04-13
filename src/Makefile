# GNU make file

SOURCES = $(shell find parsers -type f -name '*.ksy')
KAITAI_PARSERS = $(patsubst %.ksy, %.py, $(SOURCES))
SPACE:=$(EMPTY) $(EMPTY)
KAITAI_NAMES = $(notdir $(basename $(SOURCES)))
KAITAI_PATTERN = $(subst $(SPACE),\|,$(KAITAI_NAMES))
CTR_IMAGE=bang
CTR_PROGRAM=podman
# CTR_OPTIONS=-u $$(id -u):$$(id -g) 
CTR_OPTIONS=
TMPDIR=$(HOME)/tmp
KSPATH=parsers

ifdef CONTAINER
# KAITAISTRUCT_COMPILER= $(CTR_PROGRAM) container run -it --rm $(CTR_OPTIONS) -v "$(PWD)":/src:z -w /src blacktop/kaitai
KAITAISTRUCT_COMPILER= $(CTR_PROGRAM) container run -it --rm $(CTR_OPTIONS) -v "$(PWD)":/src:z -w /src kaitai
else
# Assume kaitai-struct-compiler is in $PATH
KAITAISTRUCT_COMPILER= kaitai-struct-compiler
endif

all: $(KAITAI_PARSERS)

%.py : %.ksy
	$(KAITAISTRUCT_COMPILER) -I parsers -t python --outdir `dirname "$<"` $<
	sed -i 's/^from \($(KAITAI_PATTERN)\) import /from .\1 import /' "$@"
	sed -i 's/^import \($(KAITAI_PATTERN)\)$$/from . &\nfrom .\1 import \*/' "$@"

.PHONY: test parsertests clean ctrshell ctrbuild

TEST_TMP_DIR=$(PWD)/tmp/bangtest
ifdef CONTAINER
PYTEST=$(CTR_PROGRAM) container run -it --rm $(CTR_OPTIONS) -v "$(PWD)":/src:z -v $(TEST_TMP_DIR):/bangtmp:z -w /src $(CTR_IMAGE) py.test --basetemp=/bangtmp/t
else
PYTEST=py.test --basetemp=$(TEST_TMP_DIR)/t
endif

test:
	rm -rf $(TEST_TMP_DIR)/*
	mkdir -p $(TEST_TMP_DIR)
	$(PYTEST)

parsertests:
	rm -rf $(TEST_TMP_DIR)/*
	mkdir -p $(TEST_TMP_DIR)
	$(PYTEST) parsers

ctrshell:
	$(CTR_PROGRAM) container run -it --rm $(CTR_OPTIONS) -v "$(PWD)":/src:z -v $(TMPDIR):/tmp:z -w /src $(CTR_IMAGE) bash

ctrbuild:
	$(CTR_PROGRAM) image build -t $(CTR_IMAGE) .

clean:
	rm $(KAITAI_PARSERS)

coverage:
	coverage3 run --omit "*/__init__.py","*/site-packages/*","test/*.py","parsers/*/Test.py" -m unittest discover -v -p 'Test*.py' || true
	coverage3 html -d test/coverage
	@echo Coverage report available in test/coverage/index.html
