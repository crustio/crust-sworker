.PHONY: build test build_test functionality_test clean

build:
	@$(MAKE) -C src/ all --no-print-directory

test:
	@$(MAKE) -C test/unit test --no-print-directory

build_test:
	@$(MAKE) -C test/integration build --no-print-directory

functionality_test:
	@$(MAKE) -C test/integration functionality_test --no-print-directory

clean:
	@$(MAKE) -C src/ clean --no-print-directory
	@$(MAKE) -C test/unit clean --no-print-directory
	@$(MAKE) -C test/integration clean --no-print-directory
