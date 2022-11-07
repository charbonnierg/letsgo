FROM golang:1.19-alpine as build

WORKDIR /build

# Cache go.mod for pre-downloading dependencies and only redownloading them in subsequent builds if they change
COPY go.mod go.sum ./
RUN go mod download && go mod verify
# Copy source code
COPY . .
# Build
RUN go build -v -o letsgo

FROM scratch
# Copy binary
COPY --from=build /build/letsgo /letsgo
# Define default command
CMD ["/letsgo"]
