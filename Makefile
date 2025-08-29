.PHONY: test install

PYTHON ?= python3
TEST_DIR := tests

test:
	@echo "Running unit tests..."
	@$(PYTHON) -m unittest discover -s $(TEST_DIR) -p "test_*.py" -v

install:
	@echo "This project is installable with Kevin's package manager:"
	@echo "👉 https://github.com/kevinveenbirkenbach/package-manager"
