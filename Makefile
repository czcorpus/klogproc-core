.PHONY: all build test vet clean

all: build

build:
	go build ./...

test:
	go test ./...

vet:
	go vet ./...

clean:
	go clean ./...
