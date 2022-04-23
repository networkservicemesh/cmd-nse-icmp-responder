FROM golang:1.18-bullseye as go
ENV GO111MODULE=on
ENV CGO_ENABLED=0
ENV GOBIN=/bin
RUN go install github.com/go-delve/delve/cmd/dlv@v1.6.0
RUN go install github.com/edwarnicke/dl@latest
RUN dl \
    https://github.com/spiffe/spire/releases/download/v1.2.2/spire-1.2.2-linux-x86_64-glibc.tar.gz | \
    tar -xzvf - -C /bin --strip=2 spire-1.2.2/bin/spire-server spire-1.2.2/bin/spire-agent

FROM go as build
WORKDIR /build
COPY go.mod go.sum ./
COPY ./internal/imports internal/imports
RUN go build ./internal/imports
COPY . .
RUN go build -o /bin/nse-icmp-responder .

FROM build as test
CMD go test -test.v ./...

FROM test as debug
CMD dlv -l :40000 --headless=true --api-version=2 test -test.v ./...

FROM alpine as runtime
COPY --from=build /bin/nse-icmp-responder /bin/nse-icmp-responder
ENTRYPOINT ["/bin/nse-icmp-responder"]