.PHONY: all run
all: run
run: build
	@ ./relay

.PHONY: build
build:
	@go build -o relay -ldflags="-s -w -X version.Version=1.0.0" ./cmd/relay

.PHONY: clean
clean:
	@rm relay

.PHONY: test
test:
	@go test -v ./...

.PHONY: gen-proto
gen-proto:
	@protoc -I=internal/box --go_out=internal/box internal/box/*.proto
