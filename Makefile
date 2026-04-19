.PHONY: install backend-install frontend-install lint test build dev

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
