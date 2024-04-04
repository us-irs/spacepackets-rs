# Run the following commands from root directory to build and run locally
# docker build -f automation/Dockerfile -t <NAME> .
# docker run -it <NAME>
FROM rust:latest
RUN apt-get update
RUN apt-get --yes upgrade
# tzdata is a dependency, won't install otherwise
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get --yes install rsync curl

# set CROSS_CONTAINER_IN_CONTAINER to inform `cross` that it is executed from within a container
ENV CROSS_CONTAINER_IN_CONTAINER=true

RUN rustup install nightly && \
    rustup target add thumbv7em-none-eabihf armv7-unknown-linux-gnueabihf && \
    rustup component add rustfmt clippy llvm-tools-preview

# Get grcov
RUN curl -sSL https://github.com/mozilla/grcov/releases/download/v0.8.19/grcov-x86_64-unknown-linux-gnu.tar.bz2 | tar -xj --directory /usr/local/bin
# Get nextest
RUN curl -LsSf https://get.nexte.st/latest/linux | tar zxf - -C ${CARGO_HOME:-~/.cargo}/bin

# SSH stuff to allow deployment to doc server
RUN adduser --uid 114 jenkins

# Add documentation server to known hosts
RUN echo "|1|/LzCV4BuTmTb2wKnD146l9fTKgQ=|NJJtVjvWbtRt8OYqFgcYRnMQyVw= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNL8ssTonYtgiR/6RRlSIK9WU1ywOcJmxFTLcEblAwH7oifZzmYq3XRfwXrgfMpylEfMFYfCU8JRqtmi19xc21A=" >> /etc/ssh/ssh_known_hosts
RUN echo "|1|CcBvBc3EG03G+XM5rqRHs6gK/Gg=|oGeJQ+1I8NGI2THIkJsW92DpTzs= ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBNL8ssTonYtgiR/6RRlSIK9WU1ywOcJmxFTLcEblAwH7oifZzmYq3XRfwXrgfMpylEfMFYfCU8JRqtmi19xc21A=" >> /etc/ssh/ssh_known_hosts
