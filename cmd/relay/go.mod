module github.com/kamune-org/kamune/cmd/relay

go 1.26

replace github.com/kamune-org/kamune => ../../

require (
	github.com/BurntSushi/toml v1.6.0
	github.com/coder/websocket v1.8.14
	github.com/kamune-org/kamune v0.4.0
	github.com/stretchr/testify v1.11.1
	google.golang.org/protobuf v1.36.11
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.14.1 // indirect
	gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)
