# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

.PHONY: all build clean run

all: build

build:
	$(MAKE) -C client

clean:
	$(MAKE) -C client clean
run:
	./client/host/tls_client_host ./client/enc/tls_client_enclave.signed -server:localhost -port:8443
