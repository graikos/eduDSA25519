all: build

build:
	go mod download
	go build -o ed

test:
	go test ./eddsa

clean:
	rm ed
	-rm *.txt
	-rm *.pem

.PHONY: clean all build test