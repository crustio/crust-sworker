.PHONY: build test clean

build:
	@$(MAKE) -C src/ all

test:
	@$(MAKE) -C test/ test

clean:
	@$(MAKE) -C src/ clean
	@$(MAKE) -C test/ clean
