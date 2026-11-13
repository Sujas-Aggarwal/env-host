.PHONY: build install test vet race

INSTALL_DIR ?= $(HOME)/.local/bin

build:
	go build -trimpath -o bin/envh ./cmd/envh

install:
	GOBIN="$(INSTALL_DIR)" go install ./cmd/envh
	@printf 'Installed envh to %s\n' "$(INSTALL_DIR)/envh"
	@case ":$$PATH:" in \
		*":$(INSTALL_DIR):"*) ;; \
		*) printf 'Add this directory to your shell PATH:\n  export PATH="%s:$$PATH"\n' "$(INSTALL_DIR)" ;; \
	esac

test:
	go test ./...

vet:
	go vet ./...

race:
	go test -race ./...
