FROM phusion/baseimage:0.11 as builder
LABEL description="This is the build stage for rb-node. Here we create the binary."

ENV DEBIAN_FRONTEND=noninteractive

WORKDIR /substrate

COPY . /substrate

RUN apt-get update && \
	apt-get dist-upgrade -y -o Dpkg::Options::="--force-confold" && \
	apt-get install -y cmake pkg-config libssl-dev git clang

RUN curl https://sh.rustup.rs -sSf | sh -s -- -y && \
	export PATH="$PATH:$HOME/.cargo/bin" && \
	rustup toolchain install nightly-2020-10-06 && \
	rustup target add wasm32-unknown-unknown --toolchain nightly-2020-10-06-x86_64-unknown-linux-gnu && \
	rustup default stable
RUN export PATH="$PATH:$HOME/.cargo/bin" && cargo build -p rb-node

# ===== SECOND STAGE ======

FROM phusion/baseimage:0.11
LABEL description="This is the 2nd stage: a very small image where we copy the rb-node binary."

RUN mv /usr/share/ca* /tmp && \
	rm -rf /usr/share/*  && \
	mv /tmp/ca-certificates /usr/share/ && \
	useradd -m -u 1000 -U -s /bin/sh -d /substrate substrate && \
	mkdir -p /substrate/.local/share/substrate && \
	chown -R substrate:substrate /substrate/.local && \
	ln -s /substrate/.local/share/substrate /data

COPY --from=builder /substrate/target/debug/rb-node /usr/local/bin

# checks
RUN ldd /usr/local/bin/rb-node && \
	/usr/local/bin/rb-node --version

# Shrinking
RUN rm -rf /usr/lib/python* && \
	rm -rf /usr/bin /usr/sbin /usr/share/man

USER substrate
EXPOSE 30333 9933 9944
VOLUME ["/data"]

ENV name="alice"

ENTRYPOINT /usr/local/bin/rb-node \
  --chain local \
  --port 30333 \
  --ws-port 9944 \
  --rpc-port 9933 \
  --validator \
  --execution Native \
  -lruntime=debug \
  --"$name" \
  --base-path /tmp/"$name"
