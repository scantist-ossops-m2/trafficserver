pkglib_LTLIBRARIES += avx_policy_driver/avx_policy_driver.la

# Generic link flags for all the artifacts that we build here. Note
# that we use AM_LDFLAGS to pick up important configure-time settings,
# like rpath.
AVX_POLICY_DRIVER_LD_FLAGS = \
	$(GRPC_LDFLAGS) \
	$(LIBSWOC_LDFLAGS) \
	$(AM_LDFLAGS)

AVX_POLICY_DRIVER_CPP_FLAGS = \
	$(AM_CPPFLAGS) \
	-Iavx_policy_driver \
	$(GRPC_CPPFLAGS) \
	$(LIBSWOC_CPPFLAGS)

AVX_POLICY_DRIVER_C_FLAGS = \
	$(AM_CFLAGS) \
	$(GRPC_CFLAGS) \
	$(LIBSWOC_CFLAGS)

avx_policy_driver_avx_policy_driver_la_LDFLAGS = $(AVX_POLICY_DRIVER_LD_FLAGS)
avx_policy_driver_avx_policy_driver_la_CPPFLAGS = $(AVX_POLICY_DRIVER_CPP_FLAGS)
avx_policy_driver_avx_policy_driver_la_CFLAGS = $(AVX_POLICY_DRIVER_C_FLAGS)

AVX_LAYER7_PROTO_SRCS := \
	avx_policy_driver/proto/conduit/v2/layer7.pb.cc \
	avx_policy_driver/proto/conduit/v2/layer7.grpc.pb.cc

AVX_LAYER7_PROTO_HDRS := \
	avx_policy_driver/proto/conduit/v2/layer7.pb.h \
	avx_policy_driver/proto/conduit/v2/layer7.grpc.pb.h
AVX_MICROSEG_PROTO_HDRS := avx_policy_driver/proto/conduit/v2/microseg.pb.h
AVX_MICROSEG_PROTO_SRCS := avx_policy_driver/proto/conduit/v2/microseg.pb.cc
AVX_EXTGROUPS_PROTO_HDRS := avx_policy_driver/proto/conduit/v2/external_groups.pb.h
AVX_EXTGROUPS_PROTO_SRCS := avx_policy_driver/proto/conduit/v2/external_groups.pb.cc
AVX_TYPES_PROTO_HDRS := avx_policy_driver/proto/common/types.pb.h
AVX_TYPES_PROTO_SRCS := avx_policy_driver/proto/common/types.pb.cc

policy_driver_PROTOBUF_SRCS = \
	$(AVX_LAYER7_PROTO_SRCS) \
	$(AVX_MICROSEG_PROTO_SRCS) \
	$(AVX_EXTGROUPS_PROTO_SRCS) \
	$(AVX_TYPES_PROTO_SRCS)

policy_driver_PROTOBUF_HDRS = \
	$(AVX_LAYER7_PROTO_HDRS) \
	$(AVX_MICROSEG_PROTO_HDRS) \
	$(AVX_EXTGROUPS_PROTO_HDRS) \
	$(AVX_TYPES_PROTO_HDRS)

# Tell automake to clean the generated sources.
CLEANFILES += $(policy_driver_PROTOBUF_SRCS) $(policy_driver_PROTOBUF_HDRS)

$(AVX_LAYER7_PROTO_HDRS) $(AVX_LAYER7_PROTO_SRCS): $(CLOUDN_SOURCE_ROOT)/proto/conduit/v2/layer7.proto
	$(AM_V_at)$(MKDIR_P) avx_policy_driver
	$(PROTOC) -I$(CLOUDN_SOURCE_ROOT) --cpp_out=avx_policy_driver --plugin=protoc-gen-grpc=$(GRPC_CPP_PLUGIN) --grpc_out=avx_policy_driver $<

$(AVX_MICROSEG_PROTO_HDRS) $(AVX_MICROSEG_PROTO_SRCS): $(CLOUDN_SOURCE_ROOT)/proto/conduit/v2/microseg.proto
	$(AM_V_at)$(MKDIR_P) avx_policy_driver
	$(PROTOC) -I$(CLOUDN_SOURCE_ROOT) --cpp_out=avx_policy_driver $<

$(AVX_EXTGROUPS_PROTO_HDRS) $(AVX_EXTGROUPS_PROTO_SRCS): $(CLOUDN_SOURCE_ROOT)/proto/conduit/v2/external_groups.proto
	$(AM_V_at)$(MKDIR_P) avx_policy_driver
	$(PROTOC) -I$(CLOUDN_SOURCE_ROOT) --cpp_out=avx_policy_driver $<

$(AVX_TYPES_PROTO_HDRS) $(AVX_TYPES_PROTO_SRCS): $(CLOUDN_SOURCE_ROOT)/proto/common/types.proto
	$(AM_V_at)$(MKDIR_P) avx_policy_driver
	$(PROTOC) -I$(CLOUDN_SOURCE_ROOT) --cpp_out=avx_policy_driver $<

avx_policy_driver_avx_policy_driver_la_SOURCES = \
	$(policy_driver_PROTOBUF_SRCS) \
	avx_policy_driver/web_filter.cc \
	avx_policy_driver/policy_driver.cc \
	avx_policy_driver/policy_client.cc \
	avx_policy_driver/logging.cc

# Make the sources depend on the headers since any sources may
# included generated headers. We could also use automake BUILT_SOURCES
# to solve this, but this works too.
$(avx_policy_driver_avx_policy_driver_la_SOURCES): $(policy_driver_PROTOBUF_HDRS)

noinst_PROGRAMS += \
	avx_policy_driver/test_server \
	avx_policy_driver/test_client

avx_policy_driver_test_server_SOURCES = \
	avx_policy_driver/test_server.cc \
	$(policy_driver_PROTOBUF_SRCS)

$(avx_policy_driver_test_server_SOURCES): $(policy_driver_PROTOBUF_HDRS)

avx_policy_driver_test_server_LDFLAGS = $(AVX_POLICY_DRIVER_LD_FLAGS)
avx_policy_driver_test_server_CPPFLAGS = $(AVX_POLICY_DRIVER_CPP_FLAGS)
avx_policy_driver_test_server_CFLAGS = $(AVX_POLICY_DRIVER_C_FLAGS)

avx_policy_driver_test_client_SOURCES = \
	avx_policy_driver/test_client.cc \
	$(policy_driver_PROTOBUF_SRCS)

$(avx_policy_driver_test_client_SOURCES): $(policy_driver_PROTOBUF_HDRS)

avx_policy_driver_test_client_LDFLAGS = $(AVX_POLICY_DRIVER_LD_FLAGS)
avx_policy_driver_test_client_CPPFLAGS = $(AVX_POLICY_DRIVER_CPP_FLAGS)
avx_policy_driver_test_client_CFLAGS = $(AVX_POLICY_DRIVER_C_FLAGS)

check_PROGRAMS += avx_policy_driver/unit_test_hitcounter

avx_policy_driver_unit_test_hitcounter_LDFLAGS = $(AVX_POLICY_DRIVER_LD_FLAGS)
avx_policy_driver_unit_test_hitcounter_CPPFLAGS = $(AVX_POLICY_DRIVER_CPP_FLAGS)
avx_policy_driver_unit_test_hitcounter_CFLAGS = $(AVX_POLICY_DRIVER_C_FLAGS)

avx_policy_driver_unit_test_hitcounter_SOURCES = \
        avx_policy_driver/unit_test_hitcounter.cc

# vim: ft=make ts=8 sw=8 et:
