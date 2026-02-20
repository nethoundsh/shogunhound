FROM golang:1.25-alpine AS builder
WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

ARG VERSION=vdev
RUN CGO_ENABLED=0 go build -ldflags "-X main.version=${VERSION}" -o /shogunhound ./cmd/server

FROM gcr.io/distroless/static:nonroot
COPY --from=builder /shogunhound /shogunhound
ENTRYPOINT ["/shogunhound"]
