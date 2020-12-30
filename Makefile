.PHONY: build uint_test build_integration functionality_test clean

build:
	@$(MAKE) -C src/ all --no-print-directory

build_test:
	@$(MAKE) -C test build --no-print-directory
	@$(MAKE) -C test install --no-print-directory

uint_test:
	@$(MAKE) -C test/unit test --no-print-directory

functionality_test:
	@$(MAKE) -C test functionality_test --no-print-directory

benchmark_test:
	@$(MAKE) -C test benchmark_test --no-print-directory

clean:
	@$(MAKE) -C src/ clean --no-print-directory
	@$(MAKE) -C test/unit clean --no-print-directory
	@$(MAKE) -C test clean --no-print-directory
