export PATH := ../tools/:$(PATH)

GOGO_PATH := "$(shell go list -m -f '{{.Dir}}' github.com/gogo/protobuf)"

conf.pb.go: conf.proto
	protoc --gogo_out=. -I. -I$(GOGO_PATH) $^
