.PHONY: build test clean

build:
	@$(MAKE) -C src/ all --no-print-directory

test:
	@$(MAKE) -C test/ test --no-print-directory

clean:
	@$(MAKE) -C src/ clean --no-print-directory
	@$(MAKE) -C test/ clean --no-print-directory
