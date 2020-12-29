.PHONY: build install clean

build:
	@rm -r build; cp -r src build && cp -rn ../src/* ./build
	@cd build && rm app/App.* app/process/Process.* && make clean && make -j8

install:
	@$(MAKE) -C build install --no-print-directory

clean:
	@rm -rf test_app build
	@$(MAKE) -C integration clean --no-print-directory
