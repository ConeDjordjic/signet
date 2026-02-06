.PHONY: help build run dev up down restart clean logs health
.PHONY: test test-unit test-integration test-quick
.PHONY: fmt clippy check audit lint
.PHONY: shell-db migrate reset-db
.PHONY: release docker-build

.DEFAULT_GOAL := help

# =============================================================================
# Help
# =============================================================================

help: ## Show this help message
	@printf '\n'
	@printf '\033[1;34mSignet - Role-based Access Control System\033[0m\n'
	@printf '\n'
	@printf '\033[1;32mDevelopment:\033[0m\n'
	@grep -E '^(build|run|dev|up|down|restart|clean|logs|health):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;33m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '\033[1;32mTesting:\033[0m\n'
	@grep -E '^test.*:.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;33m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '\033[1;32mCode Quality:\033[0m\n'
	@grep -E '^(fmt|clippy|check|audit|lint):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;33m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '\033[1;32mDatabase:\033[0m\n'
	@grep -E '^(shell-db|migrate|reset-db):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;33m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\n'
	@printf '\033[1;32mProduction:\033[0m\n'
	@grep -E '^(release|docker-build):.*?## .*$$' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[0;33m%-16s\033[0m %s\n", $$1, $$2}'
	@printf '\n'

# =============================================================================
# Development
# =============================================================================

build: ## Build Docker images
	@printf '\033[0;34mBuilding Docker images...\033[0m\n'
	@docker compose build

run: ## Run locally (requires DATABASE_URL and JWT_PRIVATE_KEY in .env)
	@printf '\033[0;34mStarting Signet locally...\033[0m\n'
	@cargo run

dev: ## Run with Docker in foreground with logs
	@printf '\033[0;34mStarting in development mode...\033[0m\n'
	@RUST_LOG=signet=debug,tower_http=debug docker compose up

up: ## Start all services in background
	@printf '\033[0;34mStarting services...\033[0m\n'
	@docker compose up -d
	@printf '\n'
	@printf '\033[0;32m✓\033[0m API:        http://localhost:8080\n'
	@printf '\033[0;32m✓\033[0m gRPC:       localhost:50051\n'
	@printf '\033[0;32m✓\033[0m Swagger:    http://localhost:8080/swagger-ui\n'
	@printf '\033[0;32m✓\033[0m PostgreSQL: localhost:5432\n'
	@printf '\n'
	@printf 'Use \033[0;33mmake logs\033[0m to view logs\n'
	@printf 'Use \033[0;33mmake down\033[0m to stop services\n'

down: ## Stop all services
	@printf '\033[0;33mStopping services...\033[0m\n'
	@docker compose down

restart: ## Restart all services
	@printf '\033[0;33mRestarting services...\033[0m\n'
	@docker compose restart

clean: ## Remove containers, volumes, and images
	@printf '\033[0;33mCleaning up...\033[0m\n'
	@docker compose down -v --rmi local
	@docker system prune -f

logs: ## Follow logs from all services
	@docker compose logs -f

health: ## Check API health
	@printf '\033[0;34mChecking health...\033[0m\n'
	@curl -sf http://localhost:8080/health && printf ' \033[0;32m✓ API is healthy\033[0m\n' || printf ' \033[0;31m✗ API not responding\033[0m\n'

# =============================================================================
# Testing
# =============================================================================

test: ## Run all tests with test database
	@printf '\033[0;34mStarting test database...\033[0m\n'
	@docker compose -f docker-compose.test.yml up -d
	@sleep 3
	@printf '\033[0;34mRunning tests...\033[0m\n'
	@TEST_DATABASE_URL="postgresql://signet_test:signet_test@localhost:5433/signet_test" \
		cargo test -- --test-threads=1 && \
		printf '\033[0;32m✓ All tests passed\033[0m\n' || \
		(printf '\033[0;31m✗ Tests failed\033[0m\n' && exit 1)
	@printf '\033[0;34mStopping test database...\033[0m\n'
	@docker compose -f docker-compose.test.yml down -v

test-unit: ## Run unit tests only
	@printf '\033[0;34mRunning unit tests...\033[0m\n'
	@cargo test --lib

test-integration: ## Run integration tests (requires test db)
	@printf '\033[0;34mRunning integration tests...\033[0m\n'
	@TEST_DATABASE_URL="postgresql://signet_test:signet_test@localhost:5433/signet_test" \
		cargo test --test '*' -- --test-threads=1

test-quick: ## Run tests (assumes db running)
	@printf '\033[0;34mRunning tests...\033[0m\n'
	@TEST_DATABASE_URL="postgresql://signet_test:signet_test@localhost:5433/signet_test" \
		cargo test -- --test-threads=1

# =============================================================================
# Code Quality
# =============================================================================

fmt: ## Format code
	@printf '\033[0;34mFormatting code...\033[0m\n'
	@cargo fmt

clippy: ## Run clippy linter
	@printf '\033[0;34mRunning clippy...\033[0m\n'
	@cargo clippy --all-targets --all-features -- -D warnings

check: ## Check compilation
	@printf '\033[0;34mChecking compilation...\033[0m\n'
	@cargo check --all-targets

audit: ## Security audit
	@printf '\033[0;34mRunning security audit...\033[0m\n'
	@cargo audit

lint: ## Run all code quality checks
	@printf '\033[0;34mRunning all checks...\033[0m\n'
	@cargo fmt -- --check
	@cargo clippy --all-targets --all-features -- -D warnings
	@printf '\033[0;32m✓ All checks passed\033[0m\n'

# =============================================================================
# Database
# =============================================================================

shell-db: ## Open PostgreSQL shell
	@docker compose exec postgres psql -U signet -d signet

migrate: ## Run database migrations
	@printf '\033[0;34mRunning migrations...\033[0m\n'
	@docker compose exec postgres psql -U signet -d signet -f /docker-entrypoint-initdb.d/init.sql

reset-db: ## Reset database (destroys all data!)
	@printf '\033[0;31mWARNING: This will destroy all data!\033[0m\n'
	@read -p "Continue? [y/N] " -n 1 -r; \
	echo; \
	if [ "$$REPLY" = "y" ] || [ "$$REPLY" = "Y" ]; then \
		printf '\033[0;33mResetting database...\033[0m\n'; \
		docker compose down -v; \
		docker compose up -d postgres; \
		sleep 5; \
		docker compose up -d signet; \
		printf '\033[0;32m✓ Database reset complete\033[0m\n'; \
	else \
		printf 'Cancelled\n'; \
	fi

# =============================================================================
# Production
# =============================================================================

release: ## Build optimized release binary
	@printf '\033[0;34mBuilding release binary...\033[0m\n'
	@cargo build --release
	@printf '\033[0;32m✓ Binary: target/release/signet\033[0m\n'

docker-build: ## Build production Docker image
	@printf '\033[0;34mBuilding Docker image...\033[0m\n'
	@docker build -t signet:latest .
	@printf '\033[0;32m✓ Image built: signet:latest\033[0m\n'
