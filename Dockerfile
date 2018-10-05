FROM alpine:latest
LABEL Name=ipasimulator Version=0.0.1

# The following was inspired by
# https://hub.docker.com/r/madduci/docker-cpp-env/~/dockerfile/.

VOLUME "/project"
WORKDIR "/project"
RUN apk update && \
    apk upgrade && \
    apk --update add \
        cmake \
        bash \
        ninja \
        clang && \
    rm -rf /var/cache/apk/*

ENTRYPOINT ["bash", "-c", "mkdir -p cmake && cd cmake && cmake -G Ninja .."]
