.PHONY: all clean

all:
	@$(MAKE) -C src/ all

test:
	@$(MAKE) -C test/ all

clean:
	@$(MAKE) -C src/ clean
	@$(MAKE) -C test/ clean
