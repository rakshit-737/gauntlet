PY ?= python
# Datasets live outside git; override with: make bench GAUNTLET_DATA_DIR=/path
export GAUNTLET_DATA_DIR ?= $(CURDIR)/data

.PHONY: install data kb bench demo sim test lint

install:
	$(PY) -m pip install -r requirements.txt

data:
	$(PY) scripts/download_data.py

kb:
	$(PY) -m gauntlet kb

bench:
	$(PY) -m gauntlet bench

demo:
	$(PY) -m gauntlet profiles
	$(PY) -m gauntlet plan --profile ransomware --top 15
	$(PY) -m gauntlet predict --observed T1566.001,T1059.001
	$(PY) -m gauntlet replay --profile ransomware --top 15 --ruleset sigma-core --navigator layer.json

sim:
	$(PY) -m gauntlet sim --profile ransomware
	$(PY) -m gauntlet sim --profile espionage --disable-source mail

test:
	$(PY) -m pytest -q

lint:
	$(PY) -m ruff check .
