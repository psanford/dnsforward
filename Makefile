export GOBIN = $(PWD)/tools

tools: tools.go
	egrep '^\s+_' tools.go  | awk '{print $$2}' | xargs go install

.PHONY: all
