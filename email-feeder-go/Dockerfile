FROM golang:1.26.4 AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -ldflags="-s -w" -o /feeder ./cmd/feeder

FROM gcr.io/distroless/static:nonroot
COPY --from=build /feeder /feeder
COPY --from=build /src/internal/ack/template.html /template.html
EXPOSE 9091
USER nonroot:nonroot
ENTRYPOINT ["/feeder"]
