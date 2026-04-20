BINARY 		:= capture
CMD 		:= ./cmd/capture
GOFLAGS 	:= -trimpath -ldflags="-s -w"
RACE 		:= -race

.PHONY: all build test lint vet clean deps

all: build

build:
	mkdir -p bin
	go build $(GOFLAGS) -o bin/$(BINARY) $(CMD)

build-debug:
	mkdir -p bin
	go build -o bin/$(BINARY) $(CMD)

test:
	go test $(RACE) ./...

vet:
	go vet ./...

lint:
	staticcheck ./...

deps:
	go mod tidy
	go mod download

clean:
	rm -rf bin/

run: build
	sudo ./bin/$(BINARY) -v

run-http: build
	sudo ./bin/$(BINARY) -filter "tcp port 80 or tcp port 8080" -v

run-file: build
	./bin/$(BINARY) -read $(FILE) -v