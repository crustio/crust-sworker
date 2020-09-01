.PHONY: test clean

test:
	@./build_test.sh && ./scripts/start_test.sh

clean:
	@rm -rf benchmark.report* case.log sworker.log VERSION src test_app data buildenv.mk
