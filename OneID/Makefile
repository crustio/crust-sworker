########## SGX SDK Settings ##########
SGXSDK_DIR = /home/user/sgx/sgxsdk
SGXSDK_INCDIR = $(SGXSDK_DIR)/include
SGXSDK_LIBDIR = $(SGXSDK_DIR)/lib64
SGX_ARCH = x64
SGX_DEBUG = 0
SGX_MODE = HW
SGXSSL_DIR = /opt/intel/sgxssl
SGXSSL_INCDIR = $(SGXSSL_DIR)/include
SGXSSL_LIBDIR = $(SGXSSL_DIR)/lib64
CC = gcc
CXX = g++

ifeq ($(SGX_ARCH), x86)
	SGX_COMMON_CFLAGS := -m32
	SGX_LIBRARY_PATH := $(SGXSDK_DIR)/lib
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x86/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x86/sgx_edger8r
else
	SGX_COMMON_CFLAGS := -g
	SGX_LIBRARY_PATH := $(SGXSDK_DIR)/lib64
	SGX_ENCLAVE_SIGNER := $(SGX_SDK)/bin/x64/sgx_sign
	SGX_EDGER8R := $(SGX_SDK)/bin/x64/sgx_edger8r
endif

ifeq ($(SGX_DEBUG), 1)
        SGX_COMMON_CFLAGS += -O0 -g
else
        SGX_COMMON_CFLAGS += -O2
endif

ifneq ($(SGX_MODE), HW)
	Urts_Library_Name := sgx_urts_sim
else
	Urts_Library_Name := sgx_urts
endif



########## App Settings ##########
OPENSSL_DIR := /opt/openssl/1.1.1d
OPENSSL_INCDIR := $(OPENSSL_DIR)/include
OPENSSL_LIBDIR := $(OPENSSL_DIR)/lib
App_C_Files := $(wildcard Util/*.c)
App_Cpp_Files := Application/App/App.cpp $(wildcard Util/*.cpp) $(wildcard WebService/*.cpp)
App_Include_Paths := -I/usr/include -I. -IApplication/Enclave -IWebService -IWebService/httpparser -IUtil -I$(SGXSDK_INCDIR)
App_C_Flags := $(SGX_COMMON_CFLAGS) $(App_Include_Paths) -I$(OPENSSL_INCDIR)
App_Cpp_Flags := $(App_C_Flags) -std=c++11
App_Cpp_Objects := $(App_Cpp_Files:.cpp=.o)
App_C_Objects := $(App_C_Files:.c=.o)
App_Link_Flags := -std=c++11 $(SGX_COMMON_CFLAGS) -L$(SGXSDK_LIBDIR) -L$(OPENSSL_LIBDIR) -L$(SGXSSL_LIBDIR) \
	-lsgx_ukey_exchange -lsgx_uae_service -l$(Urts_Library_Name) -l:libsgx_usgxssl.a \
	-l:libsgx_capable.a -lcurl -lcrypto -ldl -lpthread


App_Name := app


########## Enclave Settings ##########
ifneq ($(SGX_MODE), HW)
	SGX_TRTS_LIB_NAME := sgx_trts_sim
	SGX_SERVICE_LIB_NAME := sgx_tservice_sim
else
	SGX_TRTS_LIB_NAME := sgx_trts
	SGX_SERVICE_LIB_NAME := sgx_tservice
endif
SGX_CRYPTO_LIB_NAME := sgx_tcrypto

Enclave_Cpp_Files := Application/Enclave/Enclave.cpp Application/Enclave/Verify/Verify.cpp
Enclave_C_Files := 
Enclave_Include_Paths := -I$(SGXSDK_INCDIR) -I$(SGXSDK_INCDIR)/tlibc -I$(SGXSDK_INCDIR)/libcxx -I$(SGXSSL_INCDIR) -IApplication/Enclave/ -I.

Enclave_C_Flags := $(SGX_COMMON_CFLAGS) -nostdinc -fvisibility=hidden -fpic -fpie -fstack-protector -fno-builtin-printf -Wformat -Wformat-security $(Enclave_Include_Paths)
Enclave_Cpp_Flags := $(Enclave_C_Flags) -std=c++11 -nostdinc++

SGXSSL_LIBRARY_NAME := sgx_tsgxssl
SGXSSL_CRYPTO_LIBRARY_NAME := sgx_tsgxssl_crypto
SGXSSL_LINK_FLAGS :=  -L$(SGXSSL_LIBDIR) -Wl,--whole-archive -l$(SGXSSL_LIBRARY_NAME) \
	-Wl,--no-whole-archive -l$(SGXSSL_CRYPTO_LIBRARY_NAME)
Security_Link_Flags := -Wl,-z,noexecstack -Wl,-z,relro -Wl,-z,now -pie
SGXSDK_LIB_FLAGS := -L$(SGXSDK_LIBDIR)

Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles \
	$(Security_Link_Flags) -L$(SGXSDK_LIBDIR) \
	$(SGXSSL_LINK_FLAGS) \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB_NAME) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(SGX_CRYPTO_LIB_NAME) -l$(SGX_SERVICE_LIB_NAME) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 \

#Enclave_Link_Flags := $(SGX_COMMON_CFLAGS) -Wl,--no-undefined -nostdlib -nodefaultlibs -nostartfiles -L$(SGXSDK_LIBDIR) \
	$(Security_Link_Flags) \
	-Wl,--whole-archive -l$(SGX_TRTS_LIB_NAME) -Wl,--no-whole-archive \
	-Wl,--start-group -lsgx_tstdc -lsgx_tcxx -lsgx_tkey_exchange -l$(SGX_CRYPTO_LIB_NAME) -l$(SGX_SERVICE_LIB_NAME) -Wl,--end-group \
	-Wl,-Bstatic -Wl,-Bsymbolic -Wl,--no-undefined \
	-Wl,-pie,-eenclave_entry -Wl,--export-dynamic  \
	-Wl,--defsym,__ImageBase=0 $(SGXSSL_LINK_FLAGS) \

Enclave_Cpp_Objects := $(Enclave_Cpp_Files:.cpp=.o)
Enclave_C_Objects := $(Enclave_C_Files:.c=.o)

Enclave_Name := Enclave.so
Signed_Enclave_Name := Enclave.signed.so
Enclave_Config_File := Application/Enclave/Enclave.config.xml


.PHONY: all run

all: $(App_Name) $(Signed_Enclave_Name)

run: all


########## App Objects ##########

Application/App/Enclave_u.c: $(SGX_EDGER8R) Application/Enclave/Enclave.edl
	@cd Application/App && $(SGX_EDGER8R) --search-path ../Enclave --search-path $(SGXSDK_INCDIR) --search-path $(SGXSSL_INCDIR) --untrusted ../Enclave/Enclave.edl
	@echo "GEN  =>  $@"

Application/App/Enclave_u.o: Application/App/Enclave_u.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Application/App/%.o: Application/App/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Util/%.o: Util/%.c
	$(CC) $(App_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

WebService/%.o: WebService/%.cpp
	$(CXX) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(App_Name): Application/App/Enclave_u.o $(App_Cpp_Objects) $(App_C_Objects)
	$(CXX) -o $@ $^ $(App_Link_Flags)
	@echo "LINK =>  $@"


########## Enclave Objects ##########

Application/Enclave/Enclave_t.c: $(SGX_EDGER8R) Application/Enclave/Enclave.edl
	@cd Application/Enclave && $(SGX_EDGER8R) --search-path ./ --search-path $(SGXSDK_INCDIR) --search-path $(SGXSSL_INCDIR) --trusted ./Enclave.edl
	@echo "GEN  =>  $@"

Application/Enclave/Enclave_t.o: Application/Enclave/Enclave_t.c
	$(CC) $(Enclave_C_Flags) -c $< -o $@
	@echo "CC   <=  $<"

Application/Enclave/%.o: Application/Enclave/%.cpp
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

Application/Enclave/Verify/%.o: Application/Enclave/Verify/%.cpp
	$(CXX) $(Enclave_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

$(Enclave_Name): Application/Enclave/Enclave_t.o $(Enclave_Cpp_Objects) $(Enclave_C_Objects)
	$(CXX) $^ -o $@ $(Enclave_Link_Flags)
	@echo "CXX  <=  $@"

$(Signed_Enclave_Name): $(Enclave_Name)
	$(SGX_ENCLAVE_SIGNER) sign -key Application/Enclave/Enclave_private.pem -enclave $(Enclave_Name) -out $@ -config $(Enclave_Config_File)
	@echo "SIGN =>  $@"


.PHONY: clean

clean:
	@rm -f $(App_Name) $(Enclave_Name) $(Signed_Enclave_Name) $(App_Cpp_Objects) $(Enclave_Cpp_Objects) $(Enclave_C_Objects) Application/App/Enclave_u.* Application/Enclave/Enclave_t.* $(App_Cpp_Objects) $(App_C_Objects)
