build:
	go build ./...

run:
	go run main.go

clean:
	go clean

install: 
	go install
	
lint:
	golangci-lint run --enable-all

test: build
	go test -v ./parser