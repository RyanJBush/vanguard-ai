.PHONY: bootstrap lint test run-backend run-frontend

bootstrap:
	cd backend && pip install -e .[dev]
	cd frontend && npm install

lint:
	cd backend && ruff check app tests
	cd frontend && npm run lint

test:
	cd backend && pytest

run-backend:
	cd backend && uvicorn app.main:app --reload --port 8000

run-frontend:
	cd frontend && npm run dev
