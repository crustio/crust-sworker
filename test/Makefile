######## Global Settings #########
SRC_PATH := ../src/
include ../buildenv.mk

######## Test ########
TEST_SOURCES := FormatUtilsTest.cpp
TEST_TARGETS := $(TEST_SOURCES:.cpp=.test)
TEST_OBJECTS := $(TEST_SOURCES:.cpp=.o)

.PHONY: test
test: $(TEST_TARGETS)
	@for target in $(TEST_TARGETS) ; do \
		./$$target ; \
	done

%.o: %.cpp  ${SRC_PATH}app/Enclave_u.h
	@$(CXX) $(SGX_COMMON_CXXFLAGS) $(App_Cpp_Flags) -c $< -o $@
	@echo "CXX  <=  $<"

${TEST_TARGETS}: ${SRC_PATH}app/Enclave_u.o ${TEST_OBJECTS} $(App_Cpp_Objects) $(App_C_Objects)
	@$(CXX) -o $@ $^ $(App_Link_Flags)
	@chmod 755 $@
	@echo "LINK =>  $@"


######## Other ########
.PHONY: clean
clean:
	@rm ${TEST_TARGETS} ${TEST_OBJECTS}