######## Global Settings #########
SRC_PATH := ../src/
include ../buildenv.mk

######## Test ########
TEST_SOURCES := FormatUtilsTest.cpp CommonTest.cpp
TEST_OBJECTS := $(TEST_SOURCES:.cpp=.o)
TEST_TARGET := crust-tee-test

.PHONY: test build-src
test: build-src $(TEST_TARGET)
	@./${TEST_TARGET} ;

build-src: ${SRC_PATH}app/Enclave_u.h ${SRC_PATH}app/Enclave_u.o $(App_Cpp_Objects) $(App_C_Objects)
	@$(MAKE) -C ../src/ all --no-print-directory

%.o: %.cpp  ${SRC_PATH}app/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

${TEST_TARGET}: ${SRC_PATH}app/Enclave_u.o ${TEST_OBJECTS} $(App_Cpp_Objects) $(App_C_Objects)
	@$(CXX) -o $@ $^ $(App_Link_Flags)
	@chmod 755 $@
	@echo "LINK =>  $@"


######## Other ########
.PHONY: clean
clean:
	@rm -f ${TEST_TARGET} ${TEST_OBJECTS}