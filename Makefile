.PHONY: test
test:
	go test ./... -v

.PHONY: bench
bench:
	go test ./... -bench .

.PHONY: gen-proto
gen-proto:
	@protoc -I=internal/box --go_out=internal/box internal/box/*.proto