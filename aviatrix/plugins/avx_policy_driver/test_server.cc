#include <iostream>
#include <memory>
#include <string>
#include <thread>
#include <functional>
#include <tuple>
#include <vector>
#include <fstream>
#include <sstream>
#include <grpcpp/grpcpp.h>

using grpc::Server;
using grpc::ServerBuilder;
using grpc::ServerContext;
using grpc::Status;

#include "proto/conduit/v2/layer7.pb.h"
#include "proto/conduit/v2/layer7.grpc.pb.h"
/*
class ResponseList
{
  typedef std::tuple<std::string, std::function<bool(const ::MicrosegTuple *, ::L7Policy *)>> index_pair;
  std::vector<index_pair> _mylist;
  std::string _current;
public:
  void
  AddResponseObject(std::string id, std::function<bool(const ::MicrosegTuple *, ::L7Policy *)> processor)
  {
    if (_current.empty())
        _current=id;
    _mylist.emplace_back(index_pair(id, processor));
  }
  void
  Print()
  {
    for (index_pair &p : _mylist) {
      std::cout << std::get<0>(p) << std::endl;
    }
  }
  void ProcessResponse(const ::MicrosegTuple *mst, ::L7Policy *pol)
  {
    for (index_pair &p : _mylist) {
      if(_current==std::get<0>(p))
      {
        (std::get<1>(p))(mst,pol);
        break;
      }
    }
  }
  void SetCurrent(std::string current) {
    _current=current;
  }

};
*/

// ResponseList rs;

std::string
readFileIntoString(const std::string &filename)
{
  std::ifstream file(filename);
  std::stringstream buffer;
  buffer << file.rdbuf();
  return buffer.str();
}

std::string current_file;

void
ReadConfig(::Layer7Config *response)
{
  std::string json_string = readFileIntoString(current_file);
  google::protobuf::util::JsonParseOptions options2;
  auto status = JsonStringToMessage(json_string, response, options2);
  std::cout << status.message() << std::endl << "---------" << std::endl;
  std::cout << response->DebugString() << std::endl;
}

class Layer7PolicyServerImpl final : public Layer7PolicyServer::Service
{
public:
  ::grpc::Status
  GetL7PolicyConfig(::grpc::ServerContext *context, const ::EmptyArgs *request, ::Layer7Config *response) override
  {
    std::cout << "GetL7PolicyConfig 1" << std::endl;
    ReadConfig(response);
    std::cout << "GetL7PolicyConfig 2" << std::endl;
    return Status::OK;
  }
  ::grpc::Status
  UpdateHitCounters(::grpc::ServerContext *context, const ::HitCounters *request, ::HitCounterResult *response)
  {
    std::string json_string;
    google::protobuf::util::JsonPrintOptions options;
    options.add_whitespace                = true;
    options.always_print_primitive_fields = true;
    options.preserve_proto_field_names    = true;

    MessageToJsonString(*request, &json_string, options);
    response->set_result(true);
    return Status::OK;
  }
};

void
RunServer()
{
  std::string server_address("127.0.0.1:5557");
  Layer7PolicyServerImpl service;

  ServerBuilder builder;
  builder.AddListeningPort(server_address, grpc::InsecureServerCredentials());
  builder.RegisterService(&service);

  std::unique_ptr<Server> server(builder.BuildAndStart());
  std::cout << "Server listening on " << server_address << std::endl;
  server->Wait();
}

void
print_example()
{
  Layer7Config c;
  std::string json_string;

  auto policy    = c.add_policies();
  auto filter    = c.add_filters();
  auto webfilter = c.add_web_filters();
  policy->set_action(Layer7Policy_Action::Layer7Policy_Action_DENY);
  policy->set_decrypt_policy(Layer7Policy_DecryptPolicy_DECRYPT_ALLOWED);
  policy->set_log(true);
  policy->set_priority(5);
  policy->set_protocol(Layer7Policy_Protocol::Layer7Policy_Protocol_TCP);
  policy->set_watch(false);
  google::protobuf::util::JsonPrintOptions options;
  options.add_whitespace                = true;
  options.always_print_primitive_fields = true;
  options.preserve_proto_field_names    = true;
  MessageToJsonString(c, &json_string, options);
  std::cout << json_string << std::endl;
}

int
main(int argc, char **argv)
{
  bool validate = false;
  std::vector<std::string> files;
  for (int i = 1; i < argc; i++) {
    std::string curarg = std::string(argv[i]);
    std::cout << curarg << std::endl;
    if (curarg == "--validate") {
      validate = true;
    }
    if (curarg == "--example") {
      print_example();
      return 0;
    }
    if (curarg.substr(0, 2) != "--") {
      current_file = curarg;
    }
  }
  if (current_file.empty()) {
    std::cout << "Usage: test_server [file] --example --validate" << std::endl;

    return 1;
  }
  if (validate) {
    ::Layer7Config l7config;
    std::string json_string;
    google::protobuf::util::JsonParseOptions options2;
    json_string = readFileIntoString(*(files.begin()));
    std::cout << *(files.begin()) << std::endl << json_string << std::endl << "-----------------------" << std::endl;
    auto status = JsonStringToMessage(json_string, &l7config, options2);
    std::cout << status.message() << std::endl;
    std::cout << l7config.DebugString() << std::endl;
  } else {
    RunServer();
  }
  return 0;
}
