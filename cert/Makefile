GO111MODULE = on
export GO111MODULE

cert.pb.go: cert.proto .FORCE
	go build google.golang.org/protobuf/cmd/protoc-gen-go
	PATH="$(CURDIR):$(PATH)" protoc --go_out=. --go_opt=paths=source_relative $<
	rm protoc-gen-go

.FORCE:
