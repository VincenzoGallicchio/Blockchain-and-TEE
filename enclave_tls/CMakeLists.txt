# Copyright (c) Open Enclave SDK contributors.
# Licensed under the MIT License.

cmake_minimum_required(VERSION 3.11)

project("Attested TLS sample" LANGUAGES C CXX)
set(CMAKE_CXX_STANDARD 11)

find_package(OpenEnclave CONFIG REQUIRED)

add_subdirectory(client)

if ((NOT DEFINED ENV{OE_SIMULATION}) OR (NOT $ENV{OE_SIMULATION}))
  add_custom_target(
    run
    DEPENDS tls_client tls_client_enc
    COMMAND
      ${CMAKE_BINARY_DIR}/client/host/tls_client_host
      ${CMAKE_BINARY_DIR}/client/enc/tls_client_enc.signed -server:localhost
      -port:8443)
endif ()
