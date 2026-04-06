PYTHON ?= python3
UV ?= uv

.PHONY: install test mypy native format clean

install:
	$(UV) pip install -e ".[all,dev]"

native:
	cmake -B build/native src/native -DCMAKE_BUILD_TYPE=Debug
	cmake --build build/native --parallel

test:
	pytest

mypy:
	mypy --strict src

clean:
	rm -rf build .pytest_cache .mypy_cache .coverage

