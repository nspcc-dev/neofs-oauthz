FROM golang:1.21-alpine as basebuilder
RUN apk add --update make bash ca-certificates

FROM basebuilder as builder
ENV GOGC off
ENV CGO_ENABLED 0
ARG BUILD=now
ARG VERSION=dev
ARG REPO=repository
WORKDIR /src
COPY . /src

RUN make

# Executable image
FROM alpine

WORKDIR /

COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/
COPY --from=builder /src/bin/neofs-oauthz /bin/neofs-oauthz

ENTRYPOINT ["/bin/neofs-oauthz"]
