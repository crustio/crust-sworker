######## SGX SDK Settings ########

SGX_SDK ?= /opt/intel/sgxsdk
SGX_MODE ?= HW
SGX_ARCH ?= x64
SGX_DEBUG ?= 1

SGXSSL_DIR := /opt/intel/sgxssl
SGXSSL_INCDIR := $(SGXSSL_DIR)/include
SGXSSL_LIBDIR := $(SGXSSL_DIR)/lib64

SGXSSL_LIBRARY_NAME := sgx_tsgxssl
SGXSSL_CRYPTO_LIBRARY_NAME := sgx_tsgxssl_crypto
SGXSSL_LINK_FLAGS :=  -L$(SGXSSL_LIBDIR) -Wl,--whole-archive -l$(SGXSSL_LIBRARY_NAME) \
	-Wl,--no-whole-archive -l$(SGXSSL_CRYPTO_LIBRARY_NAME)

ifeq ($(shell getconf LONG_BIT), 32)
	SGX_ARCH := x86
else ifeq ($(findstring -m32, $(CXXFLAGS)), -m32)
	SGX_ARCH := x86
endif

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_FLAGS := -m32
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_FLAGS := -m64
	SGX_LIBRARY_PATH := $(SGX_SDK)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
ifeq ($(SGX_PRERELEASE), 1)
$(error Cannot set SGX_DEBUG and SGX_PRERELEASE at the same time!!)
endif
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_FLAGS += -O0 -g
else
        SGX_COMMON_FLAGS += -O2
endif

SGX_COMMON_FLAGS += -Wall -Wextra -Winit-self -Wpointer-arith -Wreturn-type \
                    -Waddress -Wsequence-point -Wformat-security \
                    -Wmissing-include-dirs -Wfloat-equal -Wundef \
                    -Wcast-align -Wcast-qual -Wredundant-decls
SGX_COMMON_CFLAGS := $(SGX_COMMON_FLAGS) -Wjump-misses-init -Wstrict-prototypes -Wunsuffixed-float-constants -Wno-pointer-sign
SGX_COMMON_CXXFLAGS := $(SGX_COMMON_FLAGS) -Wnon-virtual-dtor -std=c++11


######## App Settings ########

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif

TBB_LIBRARY_PATH := /opt/crust/tools/onetbb/lib

App_C_Files := $(wildcard app/utils/*.c)

App_Cpp_Files := app/App.cpp $(wildcard app/utils/*.cpp) $(wildcard app/config/*.cpp) \
	$(wildcard app/log/*.cpp) $(wildcard app/database/*.cpp) $(wildcard app/http/*.cpp) \
	$(wildcard app/ocalls/*.cpp) $(wildcard app/process/*.cpp) $(wildcard app/chain/*.cpp) \
	$(wildcard app/ecalls/*.cpp)
	
App_Include_Paths := -I$(SGX_SDK)/include -Iapp -Ienclave/include -Iapp/include -Iapp/utils -Iapp/http \
	-Iapp/config -Iapp/ocalls -Iapp/ecalls -Iapp/process -Iapp/chain -Iapp/log -Iapp/database

App_C_Flags := -fPIC -Wno-attributes -fopenmp $(App_Include_Paths) 

# Three configuration modes - Debug, prerelease, release
#   Debug - Macro DEBUG enabled.
#   Prerelease - Macro NDEBUG and EDEBUG enabled.
#   Release - Macro NDEBUG enabled.
ifeq ($(SGX_DEBUG), 1)
        App_C_Flags += -DDEBUG -UNDEBUG -UEDEBUG
else ifeq ($(SGX_PRERELEASE), 1)
        App_C_Flags += -DNDEBUG -DEDEBUG -UDEBUG
else
        App_C_Flags += -DNDEBUG -UEDEBUG -UDEBUG
endif

App_Cpp_Flags := $(App_C_Flags)
App_Link_Flags := -std=c++11 -L$(SGX_LIBRARY_PATH) -L$(SGXSSL_LIBDIR) -l$(Urts_Library_Name) \
	-lpthread -ldl -lboost_system -lssl -lcrypto -lleveldb -fopenmp -l:libsgx_usgxssl.a \
	-l:libsgx_capable.a -l:libsgx_tservice.a -Xlinker -zmuldefs $(App_Include_Paths) \
	-L$(TBB_LIBRARY_PATH) -ltbb

ifneq ($(SGX_MODE), HW)
	App_Link_Flags += -lsgx_uae_service_sim
else
	App_Link_Flags += -lsgx_uae_service
endif

App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Objects := $(App_C_Files:.c=.o)

App_Name := crust-sworker


######## Enclave Settings ########

ifneq ($(SGX_MODE), HW)
	Trts_Library_Name := sgx_trts_sim
	Service_Library_Name := sgx_tservice_sim
else
	Trts_Library_Name := sgx_trts
	Service_Library_Name := sgx_tservice
endif
Crypto_Library_Name := sgx_tcrypto

Enclave_Cpp_Files := enclave/Enclave.cpp $(wildcard enclave/srd/*.cpp) $(wildcard enclave/utils/*.cpp) \
	$(wildcard enclave/validator/*.cpp) $(wildcard enclave/workload/*.cpp) $(wildcard enclave/identity/*.cpp) \
	$(wildcard enclave/storage/*.cpp) $(wildcard enclave/persistence/*.cpp) $(wildcard enclave/report/*.cpp) \
	$(wildcard enclave/schedule/*.cpp)

Enclave_Include_Paths := -I$(SGX_SDK)/include -I$(SGX_SDK)/include/tlibc -I$(SGX_SDK)/include/libcxx \
	-I$(SGXSSL_INCDIR) -Ienclave -Ienclave/include -Ienclave/utils -Ienclave/identity -Ienclave/workload \
	-Ienclave/srd -Ienclave/validator -Ienclave/storage -Ienclave/persistence -Ienclave/report \
	-Ienclave/schedule
	

ifeq ($(TFLAG), 1)
	Enclave_Cpp_Files += $(wildcard enclave/utilsTest/*.cpp)
	Enclave_Include_Paths += -Ienclave/utilsTest
endif

Enclave_C_Flags := $(Enclave_Include_Paths) -nostdinc -fvisibility=hidden -fpie -ffunction-sections -fdata-sections -Wno-type-limits
CC_BELOW_4_9 := $(shell expr "`$(CC) -dumpversion`" \< "4.9")
ifeq ($(CC_BELOW_4_9), 1)
	Enclave_C_Flags += -fstack-protector
else
	Enclave_C_Flags += -fstack-protector-strong
endif

Enclave_Cpp_Flags := $(Enclave_C_Flags) -nostdinc++

# Enable the security flags
Enclave_Security_Link_Flags := -Wl,-z,relro,-z,now,-z,noexecstack

# To generate a proper enclave, it is recommended to follow below guideline to link the trusted libraries:
#    1. Link sgx_trts with the `--whole-archive' and `--no-whole-archive' options,
#       so that the whole content of trts is included in the enclave.
#    2. For other libraries, you just need to pull the required symbols.
#       Use `--start-group' and `--end-group' to link these libraries.
# Do NOT move the libraries linked with `--start-group' and `--end-group' within `--whole-archive' and `--no-whole-archive' options.
# Otherwise, you may get some undesirable errors.
Enclave_Link_Flags := $(Enclave_Security_Link_Flags) \
    -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGX_LIBRARY_PATH) \
	-L$(SGXSSL_LIBDIR) $(SGXSSL_LINK_FLAGS) \
	-Wl,--whole-archive -l$(Trts_Library_Name) -Wl,--no-whole-archive \
	-Wl,--whole-archive -lsgx_tcmalloc -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -l$(Crypto_Library_Name) -l$(Service_Library_Name) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 -Wl,--gc-sections   \
	-Wl,--version-script=enclave/Enclave.lds \
	-Wl,--allow-multiple-definition

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)

Enclave_Name := enclave.so
Signed_Enclave_Name := enclave.signed.so
Enclave_Config_File := enclave/Enclave.config.xml

ifeq ($(SGX_MODE), HW)
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = HW_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = HW_PRERELEASE
else
	Build_Mode = HW_RELEASE
endif
else
ifeq ($(SGX_DEBUG), 1)
	Build_Mode = SIM_DEBUG
else ifeq ($(SGX_PRERELEASE), 1)
	Build_Mode = SIM_PRERELEASE
else
	Build_Mode = SIM_RELEASE
endif
endif


######## Test Settings ########

Test_Source_Files := EnclaveUtilsTest.cpp MainTest.cpp
Test_Objects := $(Test_Source_Files:.cpp=.o)
Test_Target := crust-sworker-test
