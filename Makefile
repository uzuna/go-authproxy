test:
	go test ./... -v -count=1 -cover

bench:
	go test -benchmem ./ -run=^$$ -bench .

generate:
	mkdir bindata -p
	go-assets-builder assets/ -o ./bindata/data.go -p bindata