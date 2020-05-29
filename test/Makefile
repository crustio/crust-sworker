######## Global Settings #########
include ../buildenv.mk

.PHONY: test build-all
test: build-all
	@./src/$(Test_Target)

build-all:
	@cp -r ../src ./ && cp -r enclave src/ && cp ../buildenv.mk ./
	@cp *.cpp src/ && cp *.h src/
	@$(MAKE) -C src/ clean --no-print-directory
	@$(MAKE) TFLAG=1 -C src/ all --no-print-directory -j4

.PHONY: clean
clean:
	@rm -rf $(Test_Target) $(Test_Objects) src buildenv.mk
