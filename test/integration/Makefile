.PHONY: build functionality_test benchmark_test clean

build:
	@./build_test.sh

functionality_test:
	@./scripts/start_test.sh -t functionality -p $$PPID -c $(case)

benchmark_test:
	@./scripts/start_test.sh -t benchmark -p $$PPID -c $(case)

clean:
	@rm -rf benchmark.report* case.log sworker.log sworker.log2 VERSION src test_app data buildenv.mk
