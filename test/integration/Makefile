.PHONY: test clean

build:
	@./build_test.sh

functionality_test:
	@./scripts/start_test.sh functionality

benchmark_test:
	@./scripts/start_test.sh benchmark

clean:
	@rm -rf benchmark.report* case.log sworker.log VERSION src test_app data buildenv.mk
