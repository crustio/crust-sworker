include ../../buildenv.mk

define setMaxThreadNum
	enclave_para="enclave/include/Parameter.h"; \
	app_para="app/include/Resource.h"; \
	max_thread_num=$$(cat enclave/Enclave.config.xml | grep -Po "(?<=<TCSNum>).*(?=</TCSNum>)"); \
	sed -i "/^#define ENC_MAX_THREAD_NUM/c #define ENC_MAX_THREAD_NUM  $$max_thread_num" app/ecalls/ECalls.h; \
	sed -i "/^#define ENC_MAX_THREAD_NUM/c #define ENC_MAX_THREAD_NUM  $$max_thread_num" $$enclave_para; \
	cat $$app_para | grep "#define VERSION" | awk '{print $$3}' | sed 's/"//g' > ../VERSION; \
	sworker_version=$$(cat $$enclave_para | grep "#define SWORKER_VERSION" | awk '{print $$3}' | sed 's/"//g'); \
	echo "SWORKER=$$sworker_version" >> ../VERSION
endef

define addTestFlag
	if [ x"$$(grep "_CRUST_TEST_FLAG_" enclave/include/Parameter.h)" = x"" ]; then \
		sed -i "/#define _ENCLAVE_RESOURCE_H_/ a #define _CRUST_TEST_FLAG_" enclave/include/Parameter.h; \
	fi; \
	if [ x"$$(grep "EnclaveTest.edl" enclave/Enclave.edl)" = x"" ]; then \
		sed -i '/from "sgx_tsgxssl.edl" import \*;/ a \    from "EnclaveTest.edl" import \*;' enclave/Enclave.edl; \
	fi; \
	inst_dir=$$(cd `pwd`/..; pwd)/test_app; \
	sed -i "/#define CRUST_INST_DIR/ c #define CRUST_INST_DIR      \"$${inst_dir}\"" app/include/Resource.h
endef

define installTestApp
	inst_dir=$$(cd `pwd`/..; pwd)/test_app; \
	rm -rf $$inst_dir; \
    mkdir -p $${inst_dir} $${inst_dir}/bin $${inst_dir}/etc; \
    cp $(App_Name) $${inst_dir}/bin && cp $(Signed_Enclave_Name) Config.json $${inst_dir}/etc; \
	sed -i "s@\/opt\/crust\/crust-sworker\/<VERSION>@$${inst_dir}@g" $${inst_dir}/etc/Config.json
endef

ifneq ($(TFLAG), 1)
	Test_Target := 
endif

.PHONY: all target run recover install

all: .config_$(Build_Mode)_$(SGX_ARCH)
	@$(call addTestFlag)
	@$(MAKE) target

install:
	@$(call installTestApp)

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
	@cd app && $(SGX_EDGER8R) --untrusted ../enclave/Enclave.edl --search-path ../enclave --search-path $(SGX_SDK)/include --search-path $(SGXSSL_INCDIR)
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

recover:
	@$(MAKE) clean
	@find . -name "*.cpp" | grep -v "Test" | xargs -I {} rm {}
	@find . -name "*.h" | grep -v "Test" | xargs -I {} rm {}
