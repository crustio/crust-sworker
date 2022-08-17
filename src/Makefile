include ../buildenv.mk

define setMaxThreadNum
	enclave_para="enclave/include/Parameter.h"; \
	app_para="app/include/Resource.h"; \
	max_thread_num=$$(cat enclave/Enclave.config.xml | grep -Po "(?<=<TCSNum>).*(?=</TCSNum>)"); \
	sed -i "/^#define ENC_MAX_THREAD_NUM/c #define ENC_MAX_THREAD_NUM  $$max_thread_num" app/ecalls/EnclaveQueue.h; \
	sed -i "/^#define ENC_MAX_THREAD_NUM/c #define ENC_MAX_THREAD_NUM  $$max_thread_num" $$enclave_para; \
	cat $$app_para | grep "#define VERSION" | awk '{print $$3}' | sed 's/"//g' > ../VERSION; \
	sworker_version=$$(cat $$enclave_para | grep "#define SWORKER_VERSION" | awk '{print $$3}' | sed 's/"//g'); \
	echo "SWORKER=$$sworker_version" >> ../VERSION
endef

define setSGXTYPE
    sgx_type="ecdsa"; \
    for el in $$(cpuid | grep -i "sgx2 supported" | awk '{print $$NF}'); do \
        if [ x"$$el" != x"true" ]; then \
            sgx_type="epid"; \
            break; \
        fi; \
    done; \
	if [ x"$$sgx_type" = x"ecdsa" ]; then \
		resource_file="app/include/Resource.h"; \
		if [ x"$$(lsmod | grep intel_sgx)" != x"" ]; then \
			sed -i "/^#define SGX_EPID/c #define SGX_ECDSA" $$resource_file &>/dev/null; \
		else \
			echo "intel_sgx driver not found, please check and install."; \
		fi; \
	fi
endef

ifneq ($(TFLAG), 1)
	Test_Target := 
endif

.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(Test_Target)
else
target: $(App_Name) $(Signed_Enclave_Name) $(Test_Target)
ifeq ($(Build_Mode), HW_DEBUG)
	@echo "The project has been built in debug hardware mode."
else ifeq ($(Build_Mode), SIM_DEBUG)
	@echo "The project has been built in debug simulation mode."
else ifeq ($(Build_Mode), HW_PRERELEASE)
	@echo "The project has been built in pre-release hardware mode."
else ifeq ($(Build_Mode), SIM_PRERELEASE)
	@echo "The project has been built in pre-release simulation mode."
else
	@echo "The project has been built in release simulation mode."
endif

endif

run: all
ifneq ($(Build_Mode), HW_RELEASE)
	@$(CURDIR)/$(App_Name)
	@echo "RUN  =>  $(App_Name) [$(SGX_MODE)|$(SGX_ARCH), OK]"
endif

.config_$(Build_Mode)_$(SGX_ARCH):
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) app/Enclave_u.* $(Enclave_Cpp_Objects) enclave/Enclave_t.*
	@touch .config_$(Build_Mode)_$(SGX_ARCH)


######## App Objects ########

app/Enclave_u.h: $(SGX_EDGER8R) enclave/Enclave.edl
	@cd app && $(SGX_EDGER8R) --untrusted ../enclave/Enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include --search-path $(SGXSSL_INCDIR)
	@$(call setSGXTYPE)
	@echo "GEN  =>  $@"

app/Enclave_u.c: app/Enclave_u.h

app/Enclave_u.o: app/Enclave_u.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

app/utils/%.o: app/utils/%.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

app/%.o: app/%.cpp  app/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): app/Enclave_u.o $(App_Cpp_Objects) $(App_C_Objects)
	@$(CXX) -o $@ $^ $(App_Link_Flags)
	@echo "LINK =>  $@"


######## Enclave Objects ########

enclave/Enclave_t.c: $(SGX_EDGER8R) enclave/Enclave.edl
	@cd enclave && $(SGX_EDGER8R) --trusted ../enclave/Enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include --search-path $(SGXSSL_INCDIR)
	@$(call setMaxThreadNum)
	@echo "GEN  =>  $@"

enclave/Enclave_t.o: enclave/Enclave_t.c
	@$(CC) $(SGX_COMMON_CFLAGS) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

enclave/%.o: enclave/%.cpp enclave/Enclave_t.c
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): enclave/Enclave_t.o $(Enclave_Cpp_Objects)
	@$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "LINK =>  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
ifneq ($(Build_Mode), HW_RELEASE)
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/EnclavePrivate.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"
else
	@. ../scripts/prod_sign.sh
	@echo "PROD SIGN =>  $@"
endif


######## Test Objects ########

%.o: %.cpp app/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $@"

$(Test_Target): app/Enclave_u.o $(Test_Objects) $(App_Cpp_Objects) $(App_C_Objects)
	@$(CXX) -o $@ $^ $(App_Link_Flags)
	@echo "LINK =>  $@"

.PHONY: clean

clean:
	@rm -f .config_* $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) $(App_C_Objects) app/Enclave_u.* $(Enclave_Cpp_Objects) enclave/Enclave_t.*
