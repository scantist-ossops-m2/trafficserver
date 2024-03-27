/** @file

  An example program that does a null transform of response body content.

  @section license License

  Licensed to the Apache Software Foundation (ASF) under one
  or more contributor license agreements.  See the NOTICE file
  distributed with this work for additional information
  regarding copyright ownership.  The ASF licenses this file
  to you under the Apache License, Version 2.0 (the
  "License"); you may not use this file except in compliance
  with the License.  You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

  Unless required by applicable law or agreed to in writing, software
  distributed under the License is distributed on an "AS IS" BASIS,
  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
  See the License for the specific language governing permissions and
  limitations under the License.
 */

// Copyright (c) 2022, Aviatrix Systems, Inc. All rights reserved.

#include <stdio.h>
#include <unistd.h>
#include <inttypes.h>

#include "ts/ts.h"
#include "plugin.h"
#include "tee_info.h"

const char PLUGIN_NAME[] = "tee_decrypt";
namespace avx_tee_decrypt
{
DbgCtl dbg_ctl{PLUGIN_NAME};
}

int data_arg_index = -1;

const char *IDSPolicyTag = "IDSPolicy";
int IDSPolicyIndex       = -1;

class MyData
{
public:
  MyData(TSHttpTxn txnp)
  {
    this->resp_output_buffer = TSIOBufferCreate();
    this->req_output_buffer  = TSIOBufferCreate();
    this->resp_output_reader = TSIOBufferReaderAlloc(this->resp_output_buffer);
    this->req_output_reader  = TSIOBufferReaderAlloc(this->req_output_buffer);
    this->txnp               = txnp;
  }
  ~MyData()
  {
    Dbg(dbg_ctl, "Delete MyData");
    if (this->req_output_buffer) {
      TSIOBufferDestroy(this->req_output_buffer);
    }
    if (this->resp_output_buffer) {
      TSIOBufferDestroy(this->resp_output_buffer);
    }
    if (this->tee_info) {
      delete tee_info;
    }
  }
  TSVIO resp_output_vio               = nullptr;
  TSVIO req_output_vio                = nullptr;
  TSIOBuffer req_output_buffer        = nullptr;
  TSIOBufferReader req_output_reader  = nullptr;
  TSIOBuffer resp_output_buffer       = nullptr;
  TSIOBufferReader resp_output_reader = nullptr;
  TSHttpTxn txnp;
  TeeInfo *tee_info = nullptr;
};

class ContData
{
public:
  ContData(MyData *mydata) : data(mydata) {}
  ~ContData() { Dbg(dbg_ctl, "~ContData forward=%d", this->forward); }
  MyData *data = nullptr;
  bool forward = true;
};

static void
send_request_header(TSHttpTxn txnp)
{
  MyData *data = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
  TSMBuffer creq_buff;
  TSMLoc creq_loc;
  if (TS_SUCCESS != TSHttpTxnClientReqGet(txnp, &creq_buff, &creq_loc)) {
    fprintf(stderr, "Failed to get client request");
    return;
  }
  data->tee_info->send_header(creq_buff, creq_loc, true);
  TSHandleMLocRelease(creq_buff, TS_NULL_MLOC, creq_loc);
}

static void
send_response_header(TSHttpTxn txnp)
{
  MyData *data = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
  TSMBuffer sresp_buff;
  TSMLoc sresp_loc;
  if (TS_SUCCESS != TSHttpTxnServerRespGet(txnp, &sresp_buff, &sresp_loc)) {
    TSError("Failed to get server response");
    // fprintf(stderr, "Failed to get server response");
    return;
  }
  auto field_loc = TSMimeHdrFieldFind(sresp_buff, sresp_loc, TS_MIME_FIELD_TRANSFER_ENCODING, TS_MIME_LEN_TRANSFER_ENCODING);
  if (field_loc) {
    TSMimeHdrFieldRemove(sresp_buff, sresp_loc, field_loc);
  }
  data->tee_info->send_header(sresp_buff, sresp_loc, false);
  if (field_loc) {
    TSMimeHdrFieldAppend(sresp_buff, sresp_loc, field_loc);
  }
  TSHandleMLocRelease(sresp_buff, TS_NULL_MLOC, sresp_loc);
}

static void
populate_tee_info(MyData *data)
{
  if (data->tee_info == nullptr) {
    // Deferred setting up the tee_info until we knew the destination address
    sockaddr const *src_addr = TSHttpTxnOutgoingAddrGet(data->txnp); // TSHttpTxnIncomingAddrGet(data->txnp);
    sockaddr const *dst_addr = TSHttpTxnIncomingAddrGet(data->txnp); // TSHttpTxnOutgoingAddrGet(data->txnp);
    data->tee_info           = new TeeInfo{src_addr, dst_addr};
    // Go ahead and send the handshake and the request header
    data->tee_info->send_handshake();
    send_request_header(data->txnp);
  }
}

static void
check_txn_data(TSHttpTxn txnp)
{
  MyData *data = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
  populate_tee_info(data);
}

ContData *
get_cont_data(TSCont contp)
{
  ContData *conn_data = static_cast<ContData *>(TSContDataGet(contp));
  populate_tee_info(conn_data->data);
  return conn_data;
}

static void
handle_transform(TSCont contp, TSEvent event)
{
  TSVConn output_conn;
  TSVIO input_vio;
  ContData *conn_data;
  int64_t towrite;

  Dbg(dbg_ctl, "Entering handle_transform()");
  /* Get the output (downstream) vconnection where we'll write data to. */

  output_conn = TSTransformOutputVConnGet(contp);

  /* Get the write VIO for the write operation that was performed on
   * ourself. This VIO contains the buffer that we are to read from
   * as well as the continuation we are to call when the buffer is
   * empty. This is the input VIO (the write VIO for the upstream
   * vconnection).
   */
  input_vio = TSVConnWriteVIOGet(contp);

  /* Get our data structure for this operation. The private data
   * structure contains the output VIO and output buffer. If the
   * private data structure pointer is NULL, then we'll create it
   * and initialize its internals.
   */
  TSVIO output_vio;
  conn_data = get_cont_data(contp);
  if (conn_data->forward) {
    if (conn_data->data->req_output_vio == nullptr && output_conn != nullptr) {
      conn_data->data->req_output_vio = TSVConnWrite(output_conn, contp, conn_data->data->req_output_reader, INT64_MAX);
    }
    output_vio = conn_data->data->req_output_vio;
  } else if (!conn_data->forward) {
    if (conn_data->data->resp_output_vio == nullptr && output_conn != nullptr) {
      conn_data->data->resp_output_vio = TSVConnWrite(output_conn, contp, conn_data->data->resp_output_reader, INT64_MAX);
    }
    output_vio = conn_data->data->resp_output_vio;
  }

  /* Determine how much data we have left to read. For this null
   * transform plugin this is also the amount of data we have left
   * to write to the output connection.
   */

  /* We also check to see if the input VIO's buffer is non-NULL. A
   * NULL buffer indicates that the write operation has been
   * shutdown and that the upstream continuation does not want us to send any
   * more WRITE_READY or WRITE_COMPLETE events. For this simplistic
   * transformation that means we're done. In a more complex
   * transformation we might have to finish writing the transformed
   * data to our output connection.
   */
  TSIOBuffer buf_test;

  buf_test = TSVIOBufferGet(input_vio);
  if (!buf_test) {
    TSVIONBytesSet(output_vio, TSVIONDoneGet(input_vio));
    TSVIOReenable(output_vio);
    return;
  }

  towrite = TSVIONTodoGet(input_vio);
  Dbg(dbg_ctl, "\ttoWrite is %" PRId64 "", towrite);

  if (towrite > 0) {
    /* The amount of data left to read needs to be truncated by
     * the amount of data actually in the read buffer.
     */
    int64_t avail = TSIOBufferReaderAvail(TSVIOReaderGet(input_vio));
    Dbg(dbg_ctl, "\tavail is %" PRId64 "", avail);
    if (towrite > avail) {
      towrite = avail;
    }

    if (towrite > 0) {
      /* Copy the data from the read buffer to the output buffer. */
      TSIOBufferCopy(TSVIOBufferGet(output_vio), TSVIOReaderGet(input_vio), towrite, 0);

      /* Tee the packets to the side for analysis */
      Dbg(dbg_ctl, "starting send data\n");
      conn_data->data->tee_info->send_data(TSVIOReaderGet(input_vio), conn_data->forward);
      Dbg(dbg_ctl, "ending send data\n");
      /* Tell the read buffer that we have read the data and are no
       * longer interested in it.
       */
      TSIOBufferReaderConsume(TSVIOReaderGet(input_vio), towrite);

      /* Modify the input VIO to reflect how much data we've
       * completed.
       */
      TSVIONDoneSet(input_vio, TSVIONDoneGet(input_vio) + towrite);
      // TSVIONBytesSet(output_vio, TSVIONDoneGet(input_vio));
    }
  }

  /* Now we check the input VIO to see if there is data left to
   * read.
   */
  if (TSVIONTodoGet(input_vio) > 0) {
    // TSVIOReenable(output_vio);
    if (towrite > 0) {
      // TSVIONBytesSet(output_vio, towrite);
      /* If there is data left to read, then we reenable the output
       * connection by reenabling the output VIO. This will wake up
       * the output connection and allow it to consume data from the
       * output buffer.
       */
      TSVIOReenable(output_vio);

      /* Call back the input VIO continuation to let it know that we
       * are ready for more data.
       */
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_READY, input_vio);
    }
  } else {
    /* If there is no data left to read, then we modify the output
     * VIO to reflect how much data the output connection should
     * expect. This allows the output connection to know when it
     * is done reading. We then reenable the output connection so
     * that it can consume the data we just gave it.
     */
    TSVIONBytesSet(output_vio, TSVIONDoneGet(input_vio));

    if (TSVConnClosedGet(contp)) {
      Dbg(dbg_ctl, "\tVConn is closed");
      delete conn_data;
      TSContDestroy(contp);
    } else if (towrite > 0) {
      /* Call back the input VIO continuation to let it know that we
       * have completed the write operation.
       */
      TSVIOReenable(output_vio);
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_VCONN_WRITE_COMPLETE, input_vio);
    }
  }
}

static int
null_transform(TSCont contp, TSEvent event, void *edata)
{
  /* Check to see if the transformation has been closed by a call to
   * TSVConnClose.
   */
  Dbg(dbg_ctl, "Entering null_transform() event=%d", event);

  if (TSVConnClosedGet(contp)) {
    Dbg(dbg_ctl, "\tVConn is closed");
    ContData *conn_data = (ContData *)TSContDataGet(contp);
    if (conn_data) {
      delete conn_data;
    }
    TSContDestroy(contp);
    return 0;
  } else {
    switch (event) {
    case TS_EVENT_ERROR: {
      TSVIO input_vio;

      Dbg(dbg_ctl, "\tEvent is TS_EVENT_ERROR");
      /* Get the write VIO for the write operation that was
       * performed on ourself. This VIO contains the continuation of
       * our parent transformation. This is the input VIO.
       */
      input_vio = TSVConnWriteVIOGet(contp);

      /* Call back the write VIO continuation to let it know that we
       * have completed the write operation.
       */
      TSContCall(TSVIOContGet(input_vio), TS_EVENT_ERROR, input_vio);
    } break;
    case TS_EVENT_VCONN_WRITE_COMPLETE:
      Dbg(dbg_ctl, "\tEvent is TS_EVENT_VCONN_WRITE_COMPLETE");
      /* When our output connection says that it has finished
       * reading all the data we've written to it then we should
       * shutdown the write portion of its connection to
       * indicate that we don't want to hear about it anymore.
       */
      TSVConnShutdown(TSTransformOutputVConnGet(contp), 0, 1);
      break;

    /* If we get a WRITE_READY event or any other type of
     * event (sent, perhaps, because we were re-enabled) then
     * we'll attempt to transform more data.
     */
    case TS_EVENT_VCONN_WRITE_READY:
      Dbg(dbg_ctl, "\tEvent is TS_EVENT_VCONN_WRITE_READY");
      handle_transform(contp, event);
      break;
    default:
      Dbg(dbg_ctl, "\t(event is %d)", event);
      handle_transform(contp, event);
      break;
    }
  }

  return 0;
}

static void
transform_add(TSHttpTxn txnp, TSCont orig_contp)
{
  TSVConn connp, rev_connp;

  Dbg(dbg_ctl, "Entering transform_add()");
  connp                   = TSTransformCreate(null_transform, txnp);
  rev_connp               = TSTransformCreate(null_transform, txnp);
  MyData *data            = new MyData{txnp};
  ContData *conn_data     = new ContData{data};
  ContData *rev_conn_data = new ContData{data};
  rev_conn_data->forward  = false;
  TSContDataSet(connp, conn_data);
  TSContDataSet(rev_connp, rev_conn_data);
  TSUserArgSet(txnp, data_arg_index, data);
  TSHttpTxnHookAdd(txnp, TS_HTTP_RESPONSE_TRANSFORM_HOOK, rev_connp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_REQUEST_TRANSFORM_HOOK, connp);
  TSHttpTxnHookAdd(txnp, TS_HTTP_TXN_CLOSE_HOOK, orig_contp);
}

bool
IDSPolicySet(TSHttpTxn txnp)
{
  // First see if the txn arg is set
  if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_TXN, IDSPolicyTag, "IDS policy", &IDSPolicyIndex)) {
    TSError("Failed to register IDS policy index");
    return false;
  }
  void *val = TSUserArgGet(txnp, IDSPolicyIndex);
  if (val == nullptr) { // Check the vconn arg
    // Fetch the vconn from the txn
    TSHttpSsn ssnp = TSHttpTxnSsnGet(txnp);
    TSVConn vconn  = TSHttpSsnClientVConnGet(ssnp);
    if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_VCONN, IDSPolicyTag, "IDS policy", &IDSPolicyIndex)) {
      TSError("Failed to register IDS policy index");
      return false;
    }
    val = TSUserArgGet(vconn, IDSPolicyIndex);
    Dbg(dbg_ctl, "Policy arg set on vconn idx=%d val=0x%x", IDSPolicyIndex, static_cast<int>(reinterpret_cast<intptr_t>(val)));
  } else {
    Dbg(dbg_ctl, "Policy arg set on txn idx=%d val=0x%x", IDSPolicyIndex, static_cast<int>(reinterpret_cast<intptr_t>(val)));
  }
  // Do the IDS if val is not 0
  return val != nullptr;
}

static int
transform_plugin(TSCont contp, TSEvent event, void *edata)
{
  TSHttpTxn txnp = (TSHttpTxn)edata;

  Dbg(dbg_ctl, "Entering transform_plugin() event=%d", event);
  switch (event) {
  case TS_EVENT_HTTP_TXN_CLOSE: {
    Dbg(dbg_ctl, "\tEvent is TS_EVENT_HTTP_TXN_CLOSE");
    // Clean things up.
    TSHttpTxn txnp = static_cast<TSHttpTxn>(edata);
    MyData *data   = static_cast<MyData *>(TSUserArgGet(txnp, data_arg_index));
    if (data) {
      if (data->tee_info) {
        data->tee_info->send_finack();
      }
      delete data;
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  }
  case TS_EVENT_HTTP_READ_REQUEST_HDR:
    Dbg(dbg_ctl, "\tEvent is TS_EVENT_HTTP_READ_REQUEST_HDR");
    // Is this indicated by policy?
    if (IDSPolicySet(txnp)) {
      transform_add(txnp, contp);
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  case TS_EVENT_HTTP_READ_RESPONSE_HDR:
    Dbg(dbg_ctl, "\tEvent is TS_EVENT_HTTP_READ_RESPONSE_HDR");
    if (TSUserArgGet(txnp, data_arg_index) != nullptr) {
      check_txn_data(txnp);
      send_response_header(txnp);
    }
    TSHttpTxnReenable(txnp, TS_EVENT_HTTP_CONTINUE);
    return 0;
  default:
    Dbg(dbg_ctl, "\tOther Event %d", event);
    break;
  }

  return 0;
}

void
TSPluginInit(int argc, const char *argv[])
{
  TSPluginRegistrationInfo info;

  info.plugin_name   = PLUGIN_NAME;
  info.vendor_name   = "Aviatrix";
  info.support_email = "dev@trafficserver.apache.org";

  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Plugin registration failed", PLUGIN_NAME);

  } else {
    if (argc < 3) {
      TSError("[%s] Plugin failed. Requires arguments <src_gre_address> and <dst_gre_address>", PLUGIN_NAME);
      return;
    }
    TSCont contp = TSContCreate(transform_plugin, NULL);
    TSHttpHookAdd(TS_HTTP_READ_REQUEST_HDR_HOOK, contp);
    TSHttpHookAdd(TS_HTTP_READ_RESPONSE_HDR_HOOK, contp);
    TSUserArgIndexReserve(TS_USER_ARGS_TXN, "tee_data", "", &data_arg_index);
    gre_info.init(argv, argc); // Initialize some data structures
  }
  return;
}
