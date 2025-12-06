#GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '-s -w -extldflags "-static"' -o myapp-linux-amd64 main.go
CGO_ENABLED=1 GOOS=linux GOARCH=amd64 \
CC=x86_64-linux-musl-gcc \
CXX=x86_64-linux-musl-g++ \
go build -trimpath -ldflags '-s -w -extldflags "-static"' -o myapp-linux-amd64 main.go

#docker build -f Dockerfile -t myapp-builder .
#docker run --rm -v $(pwd):/output myapp-builder cp /myapp-linux-amd64 /output/

 GOOS=linux GOARCH=amd64 go build  -o gost main.go

scp -P 36000 myapp-linux-amd64 root@21.91.250.122:/root/

