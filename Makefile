.PHONY: all venv install-deps freeze lint test coverage wheel upload

all: lint coverage

venv:
	sudo apt-get -y install python3-virtualenv
	python3 -m venv venv

install-deps:
	pip install -r requirements-dev.lock

freeze:
	@pip freeze | grep -v '^pkg-resources='

lint:
	python -m flake8 soft_webauthn.py tests
	python -m pylint --ignore=example_server.py soft_webauthn.py tests
	python -m black --check soft_webauthn.py tests

test:
	python -m pytest -v

coverage:
	coverage run --source soft_webauthn -m pytest tests -x -vv
	coverage report --show-missing --fail-under 100

black:
	python -m black soft_webauthn.py tests

wheel:
	python setup.py sdist bdist_wheel
upload:
	twine upload dist/*
