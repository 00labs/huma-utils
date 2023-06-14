.PHONY: lint, lint-check, test

lint:
	poetry run autoflake --verbose -r .
	poetry run black .
	poetry run flake8 --max-line-length 120 --ignore "E203, W503" .
	poetry run isort .
	poetry run mypy --show-error-codes .
	poetry run pylint huma_utils

lint-check:
	poetry run black --check .
	poetry run flake8 --max-line-length 120 --ignore "E203, W503" .
	poetry run isort --check .
	poetry run mypy --show-error-codes .
	poetry run pylint huma_utils

test:
	ENV=test poetry run python3 -m pytest -v --cov=huma_utils --color=yes --cov-report term-missing
