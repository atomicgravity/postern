package securetunnel

// The V3 protobuf schema is vendored at proto/v3.proto and the
// generated proto/v3.pb.go is checked in so consumers don't need
// protoc on their PATH to build. Regenerate after editing the .proto:
//
//   go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
//   go generate ./internal/securetunnel/...
//
// protoc itself comes from your platform package manager (Homebrew:
// brew install protobuf; Debian/Ubuntu: apt install protobuf-compiler).

//go:generate protoc --go_out=. --go_opt=paths=source_relative proto/v3.proto
