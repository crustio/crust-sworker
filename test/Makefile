.PHONY: build install functionality_test benchmark_test clean

build:
	@rmdir --ignore-fail-on-non-empty build &>/dev/null
	@cp -r src build && cp -rn ../src/* ./build
	@cd build && rm app/App.* app/process/Process.* && make clean && make -j8

install:
	@$(MAKE) -C build install --no-print-directory

functionality_test:
	@cd integration && ./scripts/start_test.sh -t functionality -p $$PPID -c $(case)

benchmark_test:
	@cd integration && ./scripts/start_test.sh -t benchmark -p $$PPID -c $(case)

clean:
	@rm -rf test_app build
	@cd integration && rm -rf benchmark.report* case.log sworker.log sworker.log2 VERSION src data
