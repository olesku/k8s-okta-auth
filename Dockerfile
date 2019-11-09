FROM golang:1.13-alpine as builder

RUN mkdir -p /build
WORKDIR /build

RUN apk update
RUN apk add --no-cache curl git ca-certificates

COPY . .
COPY go.mod .
RUN go mod download
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags="-s -w" -o k8s-okta-auth .

FROM scratch
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /build/templates /templates
COPY --from=builder /build/k8s-okta-auth /
ENTRYPOINT [ "/k8s-okta-auth" ]
