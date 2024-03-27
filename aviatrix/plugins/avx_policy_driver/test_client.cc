#include <iostream>
#include <memory>
#include <string>

#include <grpcpp/grpcpp.h>

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

#include "proto/conduit/v2/layer7.grpc.pb.h"

class OracleClient
{
public:
  OracleClient(std::shared_ptr<Channel> channel) : stub_(Layer7PolicyServer::NewStub(channel)) {}

  ::Layer7Config *
  GetL7PolicyConfig()
  {
    Layer7Config *response = new Layer7Config();
    ClientContext context;
    ::EmptyArgs request;

    Status status = stub_->GetL7PolicyConfig(&context, request, response);

    if (status.ok()) {
      return response;
    } else {
      std::cout << "RPC failed: " << status.error_code() << "-" << status.error_details() << "-" << status.error_message()
                << std::endl;
      return nullptr;
    }
  }

private:
  std::unique_ptr<Layer7PolicyServer::Stub> stub_;
};

int
main(int argc, char **argv)
{
  std::string name("world");

  OracleClient client(grpc::CreateChannel("127.0.0.1:5557", grpc::InsecureChannelCredentials()));

  auto *message = client.GetL7PolicyConfig();
  if (message == nullptr) {
    return 1;
  }

  std::string json_string;
  google::protobuf::util::JsonPrintOptions options;
  options.add_whitespace                = true;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names    = true;
  MessageToJsonString(*message, &json_string, options);
  std::cout << json_string << std::endl;
  return 0;
}
