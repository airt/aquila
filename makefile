all: test build

run:
	go run ./bin

fmt:
	go fmt ./...

test:
	go test -v ./...

build:
	go build -o out/bin ./bin

clean:
	rm -rf out
