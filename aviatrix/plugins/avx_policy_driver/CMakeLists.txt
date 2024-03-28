set(ENV{PKG_CONFIG_PATH} "~/.local/lib/pkgconfig:/opt/ats/lib/pkgconfig")

find_package(PkgConfig REQUIRED)
find_package(protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)
pkg_check_modules(PROTOBUF REQUIRED IMPORTED_TARGET protobuf)
pkg_check_modules(GRPC REQUIRED IMPORTED_TARGET grpc++)

file(MAKE_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}/generated")
set(PROTO_BINARY_DIR "${CMAKE_CURRENT_BINARY_DIR}/generated")

add_library(
  proto-objects OBJECT
  "${CLOUDN_SOURCE_ROOT}/proto/common/types.proto" "${CLOUDN_SOURCE_ROOT}/proto/conduit/v2/layer7.proto"
  "${CLOUDN_SOURCE_ROOT}/proto/conduit/v2/microseg.proto"
  "${CLOUDN_SOURCE_ROOT}/proto/conduit/v2/external_groups.proto"
)

target_link_libraries(proto-objects PUBLIC protobuf::libprotobuf gRPC::grpc++)
target_include_directories(proto-objects PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>")

protobuf_generate(TARGET proto-objects IMPORT_DIRS "${CLOUDN_SOURCE_ROOT}" PROTOC_OUT_DIR "${PROTO_BINARY_DIR}")

protobuf_generate(
  TARGET
  proto-objects
  LANGUAGE
  grpc
  GENERATE_EXTENSIONS
  .grpc.pb.h
  .grpc.pb.cc
  PLUGIN
  "protoc-gen-grpc=\$<TARGET_FILE:gRPC::grpc_cpp_plugin>"
  IMPORT_DIRS
  ${CLOUDN_SOURCE_ROOT}
  PROTOC_OUT_DIR
  "${PROTO_BINARY_DIR}"
)

add_atsplugin(
  avx_policy_driver
  policy_driver.cc
  logging.cc
  policy_client.cc
  web_filter.cc
  ${PROTO_BINARY_DIR}/proto/conduit/v2/layer7.pb.cc
  ${PROTO_BINARY_DIR}/proto/conduit/v2/layer7.grpc.pb.cc
  ${PROTO_BINARY_DIR}/proto/conduit/v2/microseg.pb.cc
  ${PROTO_BINARY_DIR}/proto/conduit/v2/external_groups.pb.cc
  ${PROTO_BINARY_DIR}/proto/common/types.pb.cc
)

target_include_directories(
  avx_policy_driver PUBLIC "$<BUILD_INTERFACE:${PROTO_BINARY_DIR}>" ${GRPC_INCLUDES} "~/.local/include"
)
target_link_libraries(
  avx_policy_driver PRIVATE libswoc::libswoc ${PROTOBUF_LIBRARY} ${GRPC_LIBRARY} OpenSSL::Crypto OpenSSL::SSL
)

verify_global_plugin(avx_policy_driver)
