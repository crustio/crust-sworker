.PHONY: build test clean

build:
	@$(MAKE) -C src/ all --no-print-directory

test:
	@$(MAKE) -C test/unit test --no-print-directory

clean:
	@$(MAKE) -C src/ clean --no-print-directory
	@$(MAKE) -C test/unit clean --no-print-directory
	@$(MAKE) -C test/integration clean --no-print-directory
