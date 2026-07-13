.PHONY: test
test:
	go test ./... -v

.PHONY: bench
bench:
	go test ./... -bench .

.PHONY: gen-proto
gen-proto:
	@protoc -I=internal/box --go_out=internal/box internal/box/*.proto
	@protoc -I=pkg/relayconn --go_out=pkg/relayconn pkg/relayconn/pb/*.proto

.PHONY: align-structs
align-structs:
	@golangci-lint run --enable=govet --fix

.PHONY: build
build: relay bus daemon

.PHONY: relay
relay:
	cd cmd/relay && bash scripts/build.sh

.PHONY: bus
bus:
	cd cmd/bus && bash scripts/build.sh

.PHONY: daemon
daemon:
	cd cmd/daemon && bash scripts/build.sh

RELAY_VERSION ?= $(shell cat cmd/relay/VERSION 2>/dev/null | tr -d '[:space:]')
REGISTRY ?= hossein1376

.PHONY: relay-docker-push
relay-docker-push:
	docker buildx build -f cmd/relay/Dockerfile \
		--platform linux/amd64,linux/arm64 \
		-t $(REGISTRY)/kamune-relay:$(RELAY_VERSION) \
		-t $(REGISTRY)/kamune-relay:latest \
		--push .
