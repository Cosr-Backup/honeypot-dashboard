.PHONY: test test-update build up down logs

# The app uses Python 3.12-only syntax, so run the suite in a 3.12 container
# (the host interpreter may be older). Pure-stdlib app + a few test deps.
TEST_IMG = python:3.12-slim
TEST_RUN = docker run --rm -v $(CURDIR):/work -w /work $(TEST_IMG) sh -c

test:
	$(TEST_RUN) 'pip install -q -r requirements-test.txt && python -m pytest tests/ -q'

test-update:
	$(TEST_RUN) 'pip install -q -r requirements-test.txt && python -m pytest tests/ -q --snapshot-update'

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f --tail=100
