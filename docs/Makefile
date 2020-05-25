DOCS_VERIFY_SKIP ?= false
DOCS_LINT_SKIP ?= false

MOLE_DOCS_BUILD_IMAGE ?= mole-docs
MOLE_DOCS_CHECK_IMAGE ?= $(MOLE_DOCS_BUILD_IMAGE)-check
MOLE_DOCS_SERVE_IMAGE ?= $(MOLE_DOCS_BUILD_IMAGE)-serve

SITE_DIR := $(CURDIR)/site

BIND_ADDRESS := 0.0.0.0
BIND_PORT := 8000

DOCKER_RUN_DOC_PORT := 8000
DOCKER_RUN_DOC_MOUNTS := -v $(CURDIR):/mkdocs
DOCKER_RUN_DOC_OPTS := --rm $(DOCKER_RUN_DOC_MOUNTS) -p $(DOCKER_RUN_DOC_PORT):8000

DOCKER_SERVE_DOC_MOUNTS := -v $(SITE_DIR):/mkdocs/site
DOCKER_SERVE_DOC_ENV := -e BIND_ADDRESS=$(BIND_ADDRESS) -p $(BIND_PORT):8000
DOCKER_SERVE_DOC_OPS := --rm $(DOCKER_SERVE_DOC_MOUNTS) $(DOCKER_SERVE_DOC_ENV)

docs: docs-clean docs-image docs-lint docs-build docs-verify

docs-serve: docs-serve-image
	docker run $(DOCKER_SERVE_DOC_OPS) $(MOLE_DOCS_SERVE_IMAGE)

docs-serve-image:
	docker build -t $(MOLE_DOCS_SERVE_IMAGE) -f serve.Dockerfile ./

docs-image:
	docker build -t $(MOLE_DOCS_BUILD_IMAGE) -f docs.Dockerfile ./

docs-build: docs-image
	docker run $(DOCKER_RUN_DOC_OPTS) $(MOLE_DOCS_BUILD_IMAGE) sh -c "mkdocs build \
		&& chown -R $(shell id -u):$(shell id -g) ./site"

docs-verify: docs-build
	@if [ "$(DOCS_VERIFY_SKIP)" != "true" ]; then \
		docker build -t $(MOLE_DOCS_CHECK_IMAGE) -f check.Dockerfile ./; \
		docker run --rm -v $(CURDIR):/app $(MOLE_DOCS_CHECK_IMAGE) /verify.sh; \
	else \
		echo "DOCS_VERIFY_SKIP is true: no verification done."; \
	fi

docs-lint:
	@if [ "$(DOCS_LINT_SKIP)" != "true" ]; then \
		docker build -t $(MOLE_DOCS_CHECK_IMAGE) -f check.Dockerfile ./ && \
		docker run --rm -v $(CURDIR):/app $(MOLE_DOCS_CHECK_IMAGE) /lint.sh; \
	else \
		echo "DOCS_LINT_SKIP is true: no linting done."; \
	fi

docs-clean:
	rm -rf $(SITE_DIR)

.PHONY: all docs-verify docs docs-clean docs-build docs-lint
