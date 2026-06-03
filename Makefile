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
build: relay bus

.PHONY: relay
relay:
	cd cmd/relay && bash scripts/build.sh

.PHONY: bus
bus:
	cd cmd/bus && bash scripts/build.sh

# .PHONY: daemon
# daemon:
# 	go build -o daemon ./cmd/daemon
