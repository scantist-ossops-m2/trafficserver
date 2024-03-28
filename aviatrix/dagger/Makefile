# This is the base Ubuntu version to use. The user may set this to
# a different version.
UBUNTU = "22.04"

RUN := go run $(wildcard *.go)

DEVEL_IMAGE := trafficserver-devel:$(UBUNTU)
PACKAGING_IMAGE := trafficserver-packaging:$(UBUNTU)

.PHONY: help
help:
	@echo "TrafficServer meta-build system"
	@echo
	@echo "TARGETS"
	@echo
	@echo "    package          Build the TrafficServer Ubuntu package"
	@echo "    build-image      Build a base container image for development"
	@echo "    packaging-image  Build a base container image for packaging"
	@echo
	@echo "    unit-tests       Run Traffic Server unit tests"
	@echo "    regression-tests Run Traffic Server regression tests"
	@echo
	@echo "    shell            Drop into a shell in the development image"
	@echo "    clean            Remove build outputs"
	@echo
	@echo "VARIABLES"
	@echo
	@echo "    UBUNTU           Base Ubuntu version (default is $(UBUNTU))"

.PHONY: package
package:
	$(RUN) $@ --ubuntu=$(UBUNTU)

.PHONY: build-image
build-image:
	$(RUN) $@ --ubuntu=$(UBUNTU)

.PHONY: packaging-image
packaging-image:
	$(RUN) $@ --ubuntu=$(UBUNTU)

.PHONY: regression-tests
regression-tests:
	$(RUN) $@ --ubuntu=$(UBUNTU)

.PHONY: unit-tests
unit-tests:
	$(RUN) $@ --ubuntu=$(UBUNTU)

.PHONY: shell
shell:
	docker run -it --rm \
                --volume $$(cd ../.. && pwd):/src/trafficserver \
                --volume $$(cd ../../../cloudn && pwd):/src/cloudn \
                $(DEVEL_IMAGE)

.PHONY: clean
clean:
	$(RM) -r images packages
