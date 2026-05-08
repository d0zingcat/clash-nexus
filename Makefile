APP := clash-nexus
ADDR ?= 127.0.0.1:8080
DOCKER_IMAGE ?= clash-nexus

.PHONY: help install web build build-linux test serve docker-build docker-run clean

help:
	@echo "Targets:"
	@echo "  make install       Install frontend dependencies"
	@echo "  make web           Build embedded React frontend"
	@echo "  make build         Build frontend and Go binary"
	@echo "  make build-linux   Build Linux Go binary to /out/$(APP)"
	@echo "  make test          Run Go tests"
	@echo "  make serve         Build and run local web server (ADDR=$(ADDR))"
	@echo "  make docker-build  Build Docker image (DOCKER_IMAGE=$(DOCKER_IMAGE))"
	@echo "  make docker-run    Run Docker image on http://127.0.0.1:8080"
	@echo "  make clean         Remove local binary"

install:
	pnpm install

web:
	pnpm run web:build

build: web
	go build -o $(APP) .

build-linux:
	CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/$(APP) .

test:
	go test ./...

serve: build
	./$(APP) serve -addr $(ADDR)

docker-build:
	docker build -t $(DOCKER_IMAGE) .

docker-run:
	docker run --rm -p 8080:8080 $(DOCKER_IMAGE)

clean:
	rm -f $(APP)
