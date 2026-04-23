.PHONY: install backend-install frontend-install lint test build dev backend-dev frontend-dev

install: backend-install frontend-install

backend-install:
	cd backend && python -m pip install -r requirements.txt

frontend-install:
	cd frontend && npm install

lint:
	cd backend && ruff check .
	cd frontend && npm run lint

test:
	cd backend && pytest -q

build:
	cd frontend && npm run build

dev:
	docker compose up --build

backend-dev:
	cd backend && uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

frontend-dev:
	cd frontend && npm run dev
