# Run the following commands from root directory to build and run locally
# docker build -f automation/Dockerfile -t <NAME> .
# docker run -it <NAME>
FROM rust:latest
RUN apt-get update
RUN apt-get --yes upgrade
# tzdata is a dependency, won't install otherwise
ARG DEBIAN_FRONTEND=noninteractive

RUN rustup component add rustfmt clippy
