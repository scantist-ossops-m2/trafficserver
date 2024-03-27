#include <string>
#include <memory>
#include <mutex>
#include <shared_mutex>

#include <grpcpp/grpcpp.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <inttypes.h>
#include "proto/conduit/v2/layer7.grpc.pb.h"
#include "proto/conduit/v2/layer7.pb.h"
#include "proto/common/types.pb.h"

#include "ts/ts.h"
#include "plugin.h"

using grpc::Channel;
using grpc::ClientContext;
using grpc::Status;

class Layer7PolicyServerClient
{
public:
  Layer7PolicyServerClient(std::shared_ptr<Channel> channel) : stub_(Layer7PolicyServer::NewStub(channel)) {}

  Layer7Config *
  GetLayer7Policy(const EmptyArgs &request)
  {
    Layer7Config *reply = new Layer7Config();

    ClientContext context;

    Status status = stub_->GetL7PolicyConfig(&context, request, reply);

    if (status.ok()) {
      return reply;
    } else {
      std::cout << status.error_code() << ": " << status.error_message() << std::endl;
      return nullptr;
    }
  }

  const HitCounterResult *
  UpdateHitCounters(HitCounters &hit_counters)
  {
    ClientContext context;
    auto reply = new HitCounterResult();

    Status status = stub_->UpdateHitCounters(&context, hit_counters, reply);
    if (status.ok()) {
      return reply;
    } else {
      reply->set_result(false);
      reply->set_message(status.error_message());
    }
    return reply;
  }

private:
  std::unique_ptr<Layer7PolicyServer::Stub> stub_;
};

std::shared_ptr<grpc::Channel>
GetLayer7Channel()
{
  std::string address("127.0.0.1:5557");
  return grpc::CreateChannel(address, grpc::InsecureChannelCredentials());
}

Layer7Config *
FetchLayer7Policy()
{
  Layer7PolicyServerClient client(GetLayer7Channel());

  EmptyArgs args;
  Layer7Config *result = client.GetLayer7Policy(args);
  if (result == nullptr) {
    Dbg(dbg_ctl, "Null response");
    // Clear the policy argument
  } else {
    Dbg(dbg_ctl, "Policy: received");
  }
  return result;
}

const HitCounterResult *
SendLayer7PolicyHitCounters(HitCounters &hit_counters)
{
  Layer7PolicyServerClient client(GetLayer7Channel());
  return client.UpdateHitCounters(hit_counters);
}
