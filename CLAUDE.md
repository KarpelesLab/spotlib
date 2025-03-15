# SpotLib Development Guide

## Build Commands
- Build: `make` or `go build -v`
- Install dependencies: `make deps` or `go get -v -t .`
- Run all tests: `make test` or `go test -v`
- Run single test: `go test -v -run TestName`
- Format code: `goimports -w -l .`

## Code Style Guidelines
- **Imports**: Standard lib first, then third-party packages after blank line
- **Naming**: Public (CamelCase), private (lowerCamelCase), descriptive names
- **Error Handling**: Early returns, error wrapping with `fmt.Errorf("%w", err)`
- **Formatting**: Follow Go standard formatting with `goimports`
- **Comments**: GoDoc style for exported funcs/types, inline for complex logic
- **Types**: Clear interfaces, functional handler types
- **Receivers**: Single-letter abbreviations (e.g., `c *Client`)
- **Concurrency**: Proper mutex usage with defers for unlock
- **Context**: Pass context.Context for timeout/cancellation support
- **Testing**: Package ends with _test, thorough test cases, clear error messages

Remember to run tests before committing changes. The project follows idiomatic Go practices.