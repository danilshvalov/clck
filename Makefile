.PHONY: build

conan-debug:
	conan install . --build=missing --settings=build_type=Debug

conan-release:
	conan install . --build=missing --settings=build_type=Release

build-debug: conan-debug
	cmake --preset conan-debug
	cmake --build --preset conan-debug

build-release: conan-release
	cmake --preset conan-release
	cmake --build --preset conan-release

