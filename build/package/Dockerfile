## Build the executable in the first stage
FROM golang:1.22.3-alpine3.19 AS build

WORKDIR /go/app

COPY go.mod .
COPY go.sum .

RUN go mod download

COPY . .

RUN go build -o server-alpha ./cmd/server

## Serve only the compiled binary in the second stage
FROM alpine:3.19 AS serve

# Change working directory to /go/app
WORKDIR /go/app

# Add a non-root user and group
RUN addgroup -S appgroup && adduser -S appuser -G appgroup

# Create a directory for the key files
RUN mkdir -p /go/app/keys && chown -R appuser:appgroup /go/app/keys

# Copy the Pre-built binary file from the previous stage
COPY --from=build /go/app/server-alpha /go/app/server-alpha

# Copy the key files
RUN chown -R appuser:appgroup /go/app

# Switch to the newly created user.
USER appuser

CMD ["./server-alpha"]