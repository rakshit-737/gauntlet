PY ?= python

.PHONY: demo test install

install:
	$(PY) -m pip install -r requirements.txt

test:
	$(PY) -m pytest -q

demo:
	$(PY) -m gauntlet plan --profile ransomware --top 10
	$(PY) -m gauntlet run --profile ransomware
	$(PY) -m gauntlet run --profile espionage --disable-source mail
