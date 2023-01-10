# Run the following commands from root directory to build and run locally
# docker build -f automation/Dockerfile -t <NAME> .
# docker run -it <NAME>
FROM rust:latest
RUN apt-get update
RUN apt-get --yes upgrade
# tzdata is a dependency, won't install otherwise
ARG DEBIAN_FRONTEND=noninteractive

# set CROSS_CONTAINER_IN_CONTAINER to inform `cross` that it is executed from within a container
ENV CROSS_CONTAINER_IN_CONTAINER=true

RUN rustup install nightly && \
    rustup target add thumbv7em-none-eabihf armv7-unknown-linux-gnueabihf && \
    rustup component add rustfmt clippy
