include ../buildenv.mk

define setMaxThreadNum
	max_thread_num=$$(cat enclave/Enclave.config.xml | grep -Po "(?<=<TCSNum>).*(?=</TCSNum>)"); \
	sed -i "/^#define ENC_MAX_THREAD_NUM/c #define ENC_MAX_THREAD_NUM  $$max_thread_num" app/ecalls/ECalls.h; \
	sed -i "/^#define ENC_MAX_THREAD_NUM/c #define ENC_MAX_THREAD_NUM  $$max_thread_num" enclave/Parameter.h; \
	cat include/Resource.h | grep "#define VERSION" | awk '{print $$3}' | sed 's/"//g' > ../VERSION; \
	tee_version=$$(cat enclave/Parameter.h | grep "#define TEE_VERSION" | awk '{print $$3}' | sed 's/"//g'); \
	echo "TEE=$$tee_version" >> ../VERSION
endef

ifneq ($(TFLAG), 1)
	Test_Target := 
endif

.PHONY: all target run
all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(MAKE) target

ifeq ($(Build_Mode), HW_RELEASE)
target:  $(App_Name) $(Enclave_Name) $(Test_Target)
	@echo "The project has been built in release hardware mode."
	@echo "Please sign the $(Enclave_Name) first with your signing key before you run the $(App_Name) to launch and access the enclave."
	@echo "To sign the enclave use the command:"
	@echo "   $(SGX_ENCLAVE_SIGNER) sign -key <your key> -enclave $(Enclave_Name) -out <$(Signed_Enclave_Name)> -config $(Enclave_Config_File)"
	@echo "You can also sign the enclave using an external signing tool."
	@echo "To build the project in simulation mode set SGX_MODE=SIM. To build the project in prerelease mode set SGX_PRERELEASE=1 and SGX_MODE=HW."


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
	cd app && $(SGX_EDGER8R) --untrusted ../enclave/Enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include --search-path $(SGXSSL_INCDIR)
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
	@$(SGX_ENCLAVE_SIGNER) sign -key enclave/EnclavePrivate.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


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
