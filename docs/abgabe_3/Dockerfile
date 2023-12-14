## Build the executable in the first stage
FROM golang:1.21.5-alpine3.17 AS build

WORKDIR /go/app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o server-alpha ./cmd/server

## Serve only the compiled binary in the second stage
FROM alpine:3.17.6 AS serve

## Neccessary to run a health check in our docker-compose file
RUN apk --update --no-cache add curl

# Copy the Pre-built binary file from the previous stage
COPY --from=build /go/app/server-alpha /go/app/server-alpha

CMD ["/go/app/server-alpha"]