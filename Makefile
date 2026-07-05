# Alaniz Cipher — reproducibility entry points (reference path is galois-free).

.PHONY: install test reproduce-all algebra-check clean

install:
	python -m pip install -r requirements.txt

test:
	python -m pytest -q

# Detect + self-test the algebra backend used for AO cryptanalysis at scale.
algebra-check:
	python experiments/check_algebra_env.py

# One-command reproduction of the fast, deterministic baseline.
# Portable equivalent (no `make` needed): python experiments/reproduce_all.py
reproduce-all:
	python experiments/reproduce_all.py

clean:
	find . -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name .pytest_cache -prune -exec rm -rf {} + 2>/dev/null || true
