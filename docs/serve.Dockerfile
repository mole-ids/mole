FROM alpine:3.10

ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/root/.local/bin

ENV BIND_ADDRESS=0.0.0.0

WORKDIR /mkdocs
VOLUME /mkdocs

RUN apk --no-cache --no-progress add python3

ENTRYPOINT python3 -m http.server --bind $BIND_ADDRESS --directory ./site 8000
