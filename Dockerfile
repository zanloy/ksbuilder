FROM golang:1.17.1-alpine3.13 AS builder

# Setup VA certs for downloading on VPN
RUN su root -c "apk --no-cache add ca-certificates"
COPY certs/* /usr/local/share/ca-certificates/
RUN su root -c "update-ca-certificates"

# Setup environment
ENV CGO_ENABLED=0 \
    GOOS=linux \
    GOARCH=amd64

# Move to the appropriate working directory
WORKDIR /build

# Copy and download dependency go modules
COPY go.mod .
COPY go.sum .
RUN go mod download

# Copy the code into the container
COPY . .

# Build our application
RUN go build -o ksbuilder .

# Build our final (smaller) image
FROM zanloy/alpine-va:3.13.3

# Set working dir /app
WORKDIR /app

RUN mkdir -p /app/certs

# Copy in our default ca directory
COPY ca /app/ca

# Copy in ksbuilder binary from builder image
COPY --from=builder /build/ksbuilder /app/

# Command to run by default
CMD ["/app/ksbuilder"]
