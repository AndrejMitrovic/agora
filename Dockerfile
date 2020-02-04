# Build Agora from source
FROM alpine:edge AS Builder
ARG DUB_OPTIONS
RUN apk --no-cache add build-base dub git libsodium-dev openssl openssl-dev sqlite-dev zlib-dev
RUN apk --no-cache add -X http://dl-cdn.alpinelinux.org/alpine/edge/testing ldc dtools-rdmd
ADD . /root/agora/
WORKDIR /root/agora/
RUN dub --verror test --skip-registry=all --compiler=ldc2
