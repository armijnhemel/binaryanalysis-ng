# GNU make file

SOURCES = $(shell find parsers -type f -name '*.ksy')
KAITAI_PARSERS = $(patsubst %.ksy, %.py, $(SOURCES))
SPACE:=$(EMPTY) $(EMPTY)
KAITAI_NAMES = $(notdir $(basename $(SOURCES)))
KAITAI_PATTERN = $(subst $(SPACE),\|,$(KAITAI_NAMES))
DOCKER_IMAGE=bang

ifdef DOCKER
# KAITAISTRUCT_COMPILER= docker container run -it --rm -u $$(id -u):$$(id -g) -v "$(PWD)":/src:z -w /src blacktop/kaitai
KAITAISTRUCT_COMPILER= docker container run -it --rm -u $$(id -u):$$(id -g) -v "$(PWD)":/src:z -w /src kaitai
else
# Assume kaitai-struct-compiler is in $PATH
KAITAISTRUCT_COMPILER= kaitai-struct-compiler 
endif

all: $(KAITAI_PARSERS)

%.py : %.ksy
	$(KAITAISTRUCT_COMPILER) -t python --outdir `dirname "$<"` $<
	sed -i 's/^from \($(KAITAI_PATTERN)\) import /from .\1 import /' "$@"
	sed -i 's/^import \($(KAITAI_PATTERN)\)$$/from . &/' "$@"

.PHONY: test parsertests clean dockershell dockerbuild

TEST_TMP_DIR=$(PWD)/tmp/bangtest
ifdef DOCKER
PYTEST=docker container run -it --rm -u $$(id -u):$$(id -g) -v "$(PWD)":/src:z -v $(TEST_TMP_DIR):/bangtmp:z -w /src $(DOCKER_IMAGE) py.test --basetemp=/bangtmp/t
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

dockershell:
	docker container run -it --rm -u $$(id -u):$$(id -g) -v "$(PWD)":/src:z -v /tmp:/tmp:z -w /src $(DOCKER_IMAGE) bash

dockerbuild:
	docker image build -t $(DOCKER_IMAGE) .

clean:
	rm $(KAITAI_PARSERS)

coverage:
	coverage3 run --omit "*/__init__.py","*/site-packages/*","test/*.py","parsers/*/Test.py" -m unittest discover -v -p 'Test*.py' || true
	coverage3 html -d test/coverage
	@echo Coverage report available in test/coverage/index.html
