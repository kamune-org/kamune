.PHONY: all
all: run
run:
	@go run ./cmd/relay
.PHONY: test
test:
	@go test -v ./...
.PHONY: gen-proto
gen-proto:
	@protoc -I=internal/box --go_out=internal/box internal/box/*.proto
