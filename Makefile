.PHONY: docs
init-actions:
	python -m pip install --upgrade pip
	python -m pip install -r requirements-dev.txt
	python -m autoflake --in-place --remove-all-unused-imports --ignore-init-module-imports .
	python -m black tls_requests
	python -m isort tls_requests
	python -m flake8 tls_requests


test:
	tox -p
	rm -rf *.egg-info

test-readme:
	python setup.py check --restructuredtext --strict && ([ $$? -eq 0 ] && echo "README.md and CHANGELOG.md ok") || echo "Invalid markup in README.md or CHANGELOG.md!"

pytest:
	python -m pytest tests

coverage:
	python -m pytest --cov-config .coveragerc --verbose --cov-report term --cov-report xml --cov=tls_requests tests

docs:
	mkdocs serve

publish-test-pypi:
	python -m pip install -r requirements-dev.txt
	python -m pip install 'twine>=6.0.1'
	python setup.py sdist bdist_wheel
	twine upload --repository testpypi --skip-existing dist/*
	rm -rf build dist .egg wrapper_tls_requests.egg-info

publish-pypi:
	python -m pip install -r requirements-dev.txt
	python -m pip install 'twine>=6.0.1'
	python setup.py sdist bdist_wheel
	twine upload --skip-existing dist/*
	rm -rf build dist .egg wrapper_tls_requests.egg-info
