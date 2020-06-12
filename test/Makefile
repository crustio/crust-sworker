######## Global Settings #########
include ../buildenv.mk

define addTestFunctions
	enc_cpp_fun="\\\nbool ecall_test_inner_apis()\n{\n\treturn test_utils();\n}"; \
	enc_cpp_inc="#include \"UtilsTest.h\""; \
	enc_edl_fun="\\\t\t// For test\n\t\tpublic bool ecall_test_inner_apis();\n"; \
	enc_edl_inc="\\\tinclude \"stdbool.h\""; \
	sed -i "$$ a $$enc_cpp_fun" src/enclave/Enclave.cpp; \
	sed -i "1 i $$enc_cpp_inc" src/enclave/Enclave.cpp; \
	sed -i "/\btrusted\b {/a $$enc_edl_fun" src/enclave/Enclave.edl; \
	sed -i "/\benclave\b {/a $$enc_edl_inc" src/enclave/Enclave.edl
endef

.PHONY: test build-all
test: build-all
	@./src/$(Test_Target)

build-all:
	@cp -r ../src ./ && cp -r enclave src/ && cp ../buildenv.mk ./
	@cp *.cpp src/ && cp *.h src/
	@$(call addTestFunctions)
	@$(MAKE) -C src/ clean --no-print-directory
	@$(MAKE) TFLAG=1 -C src/ all --no-print-directory -j4

.PHONY: clean
clean:
	@rm -rf $(Test_Target) $(Test_Objects) src buildenv.mk
