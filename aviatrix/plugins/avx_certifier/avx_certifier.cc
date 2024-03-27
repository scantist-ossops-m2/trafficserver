// Copyright (c) 2022, Aviatrix Systems, Inc. All rights reserved.

// TODOS:
// * refactor/simplify the cont handlers in certifier
// * implement timeout for the probe origin connection
//     in the records.config we now use an infinite handshake timeout
// * limit disk usage to prevent DDOS
// * Remove dead code

// * ...

// DONE:
// * copy enddate from origin
// * implement expiration logic for the certs
// * enforce short expiration timeouts even when origin cert has a long one -- this is
//   prevent having same local certs for a long time
// * encode special characters for filesystem paths to prevent path traversing
// * fix Certifier class delete in (leaks now by design)
//       the Resume... functions are the end of the logical flow
//       we could still have events on the probe vconn/vio continuation after that?
//       we need to be sure that we won't run into a race condition there
// * fix cont cleanups
// * do a zero byte wri`te into the probe connection to force TLS handshake
//     this is now a 2 byte (spaces), which could cause the origin to close
//     on us before we can process the handshake

#include <atomic>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <getopt.h>

#include <time.h>

#include <sys/stat.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/conf.h>
#include <openssl/x509v3.h>
#include <openssl/x509.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/bio.h>
#include <openssl/opensslv.h>

#include <unordered_map> // cnDataMap
#include <queue>         // vconnQ
#include <string>        // std::string
#include <fstream>       // ofstream
#include <memory>
#include <algorithm>

#include "ts/ts.h"

namespace
{
const char *PLUGIN_NAME = "certifier";
DbgCtl dbg_ctl{PLUGIN_NAME};
} // namespace
const char *no_sni_servername_placeholder_domain = "placeholder.no.sni.hostname.certificate";
const int ASSUME_EXPIRED_TIME                    = 10 * 60;
const int RETRY_TIME                             = 5 * 60;
const int MAX_CERT_EXP_TIME                      = 7 * 24 * 3600;
const char *CertifierPolicyTag                   = "CertifierPolicy";

/// Override default delete for unique ptrs to openSSL objects
namespace std
{
template <> struct default_delete<X509> {
  void
  operator()(X509 *n)
  {
    if (n != nullptr)
      X509_free(n);
  }
};
template <> struct default_delete<X509_REQ> {
  void
  operator()(X509_REQ *n)
  {
    if (n != nullptr)
      X509_REQ_free(n);
  }
};
template <> struct default_delete<EVP_PKEY> {
  void
  operator()(EVP_PKEY *n)
  {
    if (n != nullptr)
      EVP_PKEY_free(n);
  }
};
template <> struct default_delete<SSL_CTX> {
  void
  operator()(SSL_CTX *n)
  {
    if (n != nullptr)
      SSL_CTX_free(n);
  }
};
} // namespace std

/// Name aliases for unique pts to openSSL objects
using scoped_X509     = std::unique_ptr<X509>;
using scoped_X509_REQ = std::unique_ptr<X509_REQ>;
using scoped_EVP_PKEY = std::unique_ptr<EVP_PKEY>;
using scoped_SSL_CTX  = std::unique_ptr<SSL_CTX>;

class SslLRUList
{
private:
  struct SslData {
    std::queue<void *> vconnQ;    ///< Current queue of connections waiting for cert
    std::unique_ptr<SSL_CTX> ctx; ///< Context generated
    scoped_X509 cert;             ///< Cert generated
    std::string commonName;       ///< SNI
    bool scheduled = false;       ///< If a TASK thread has been scheduled to generate cert
                                  ///< The first thread might fail to do so, this flag will help reschedule
    bool wontdo = false;          ///< if certs not on disk and dynamic gen is disabled
    /// Doubly Linked List pointers for LRU
    SslData *prev = nullptr;
    SslData *next = nullptr;

    time_t exptime;
    time_t begintime;

    SslData() = default;
    ~SslData() { Dbg(dbg_ctl, "Deleting ssl data for [%s]", commonName.c_str()); }
  };

  using scoped_SslData = std::unique_ptr<SslLRUList::SslData>;

  // unordered_map is much faster in terms of insertion/lookup/removal
  // Although it uses more space than map, the time efficiency should be more important
  std::unordered_map<std::string, scoped_SslData> cnDataMap; ///< Map from CN to sslData
  TSMutex list_mutex;

  int size = 0;
  int limit;
  SslData *head = nullptr;
  SslData *tail = nullptr;

public:
  SslLRUList(int in_limit = 4096) : limit(in_limit) { list_mutex = TSMutexCreate(); }

  ~SslLRUList() { TSMutexDestroy(list_mutex); }

  // Returns valid ptr to SSL_CTX if successful lookup
  //         nullptr if not found and create SslData in the map
  SSL_CTX *
  lookup_and_create(const char *servername, void *edata, bool &wontdo, bool &delete_cert_from_disk, bool &lookup_scheduled)
  {
    SslData *ssl_data              = nullptr;
    scoped_SslData scoped_ssl_data = nullptr;
    SSL_CTX *ref_ctx               = nullptr;
    std::string commonName(servername);
    lookup_scheduled = false;
    TSMutexLock(list_mutex);
    auto dataItr = cnDataMap.find(commonName);
    /// If such a context exists in dict
    if (dataItr != cnDataMap.end()) {
      ssl_data = dataItr->second.get();
      // if expired reset ssl data entry struct and set ssl data to null and delete_cert_from_disk=True
      // else ...
      time_t nowtime = time(nullptr);
      if (ssl_data->exptime != -1 && ssl_data->exptime - 15 < nowtime) {
        ssl_data->ctx.reset(nullptr);
        ssl_data->cert.reset(nullptr);
        ssl_data->scheduled   = false;
        ssl_data->exptime     = -1;
        ssl_data->begintime   = -1;
        ssl_data->wontdo      = false;
        delete_cert_from_disk = true;

        Dbg(dbg_ctl, "clearing the ssl_data struct because cert expired");
      }

      /// Reuse context if already built, self queued if not
      if (ssl_data->wontdo) {
        wontdo = true;
      } else if (ssl_data->ctx) {
        ref_ctx = ssl_data->ctx.get();
      } else {
        if (ssl_data->vconnQ.size() > 0) {
          lookup_scheduled = true;
        }
        ssl_data->vconnQ.push(edata);
      }
    }
    if (ssl_data == nullptr) {
      /// Add a new ssl_data to dict if not exist
      scoped_ssl_data.reset(new SslData);
      ssl_data             = scoped_ssl_data.get();
      ssl_data->commonName = std::move(commonName);
      ssl_data->vconnQ.push(edata);
      ssl_data->exptime   = -1;
      ssl_data->begintime = -1;

      cnDataMap[ssl_data->commonName] = std::move(scoped_ssl_data);
    }
    // With a valid sslData pointer
    if (ssl_data != nullptr) {
      // Add to the list and set scheduled flag
      prepend(ssl_data);
      if (ref_ctx == nullptr || !ssl_data->scheduled) {
        ssl_data->scheduled = true;
      }
    }
    TSMutexUnlock(list_mutex);
    return ref_ctx;
  }

  // Setup ssldata 1) ctx 2) cert 3) swapping queue
  // Ownership of unique pointers are transferred into this function
  // Then if the entry is found, the ownership is further transferred to the entry
  // if not, the objects are destroyed here. (As per design, this is caused by LRU management deleting oldest entry)
  void
  setup_data_ctx(const std::string &commonName, std::queue<void *> &localQ, std::unique_ptr<SSL_CTX> ctx, scoped_X509 cert,
                 const bool &wontdo, time_t exp_time_cert, time_t begin_time_cert)
  {
    TSMutexLock(list_mutex);
    auto iter = cnDataMap.find(commonName);
    if (iter != cnDataMap.end()) {
      std::swap(localQ, iter->second->vconnQ);
      iter->second->ctx       = std::move(ctx);
      iter->second->cert      = std::move(cert); ///< We might not need cert, can be easily removed
      iter->second->wontdo    = wontdo;
      iter->second->exptime   = exp_time_cert;
      iter->second->begintime = begin_time_cert;
    }
    TSMutexUnlock(list_mutex);
  }

  // Prepend to the LRU list
  void
  prepend(SslData *data)
  {
    TSMutexLock(list_mutex);
    std::unique_ptr<SslData> local = nullptr;
    if (data != nullptr) {
      // If data is the most recent node in the list,
      // we leave it unchanged.
      if (head != data) {
        // Remove data from the list (does size decrement)
        remove_from_list(data);

        // Prepend to head
        data->prev = nullptr;
        data->next = head;
        if (data->next != nullptr) {
          data->next->prev = data;
        }
        head = data;
        if (tail == nullptr) {
          tail = data;
        }

        // Remove oldest node if size exceeds limit
        if (++size > limit) {
          Dbg(dbg_ctl, "Removing %s", tail->commonName.c_str());
          auto iter = cnDataMap.find(tail->commonName);
          if (iter != cnDataMap.end()) {
            local = std::move(iter->second); // copy ownership
            cnDataMap.erase(iter);
          }
          if ((tail = tail->prev) != nullptr) {
            tail->next = nullptr;
          }
          size -= 1;
        }
      }
    }
    Dbg(dbg_ctl, "%s Prepend to LRU list...List Size:%d Map Size: %d", data->commonName.c_str(), size,
        static_cast<int>(cnDataMap.size()));

    TSMutexUnlock(list_mutex);
  }

  // Remove list node
  void
  remove_from_list(SslData *data)
  {
    TSMutexLock(list_mutex);
    // If data and list are both valid
    if (data != nullptr) {
      // If data is linked in list
      if (data->prev != nullptr || data->next != nullptr || head == data) {
        if (data->prev != nullptr) {
          data->prev->next = data->next;
        }
        if (data->next != nullptr) {
          data->next->prev = data->prev;
        }
        if (head == data) {
          head = data->next;
        }
        if (tail == data) {
          tail = data->prev;
        }
        data->prev  = nullptr;
        data->next  = nullptr;
        size       -= 1;
      }
    }
    TSMutexUnlock(list_mutex);
  }

  SslData *
  get_newest()
  {
    TSMutexLock(list_mutex);
    SslData *ret = head;
    TSMutexUnlock(list_mutex);
    return ret;
  }

  SslData *
  get_oldest()
  {
    TSMutexLock(list_mutex);
    SslData *ret = tail;
    TSMutexUnlock(list_mutex);
    return ret;
  }

  int
  get_size()
  {
    TSMutexLock(list_mutex);
    int ret = size;
    TSMutexUnlock(list_mutex);
    return ret;
  }

  // Set scheduled flag
  int
  set_schedule(const std::string &commonName, bool flag)
  {
    int ret = -1;
    TSMutexLock(list_mutex);
    auto iter = cnDataMap.find(commonName);
    if (iter != cnDataMap.end()) {
      iter->second->scheduled = flag;
      ret                     = 0;
    }
    TSMutexUnlock(list_mutex);
    return ret;
  }
};

// Flag for dynamic cert generation
static bool sign_enabled = false;

// Trusted CA private key and cert
static scoped_X509 ca_cert_scoped;
static scoped_EVP_PKEY ca_pkey_scoped;
// static scoped_EVP_PKEY  ts_pkey_scoped;

static int ca_serial;            ///< serial number
static std::fstream serial_file; ///< serial number file
static TSMutex serial_mutex;     ///< serial number mutex

// Management Object
static std::unique_ptr<SslLRUList> ssl_list = nullptr;
static std::string store_path;

/// Local helper function that generates a CSR based on common name
static scoped_X509_REQ
mkcsr(const scoped_X509 &source_cert)
{
  Dbg(dbg_ctl, "Entering mkcsr()...");
  X509_NAME *n;
  scoped_X509_REQ req;
  req.reset(X509_REQ_new());

  /// Set X509 version
  X509_REQ_set_version(req.get(), 1);

  /// Get handle to subject name
  auto subject = X509_get_subject_name(source_cert.get());
  X509_REQ_set_subject_name(req.get(), subject);
  int san_nid   = NID_subject_alt_name;
  int san_index = X509_get_ext_by_NID((source_cert.get()), san_nid, -1);
  if (san_index != -1) {
    X509_EXTENSION *san_ext = X509_get_ext((source_cert.get()), san_index);
    // Create a new stack of extensions
    STACK_OF(X509_EXTENSION) *exts = sk_X509_EXTENSION_new_null();

    // Add the SAN extension to the stack of extensions
    sk_X509_EXTENSION_push(exts, san_ext);

    // Add the stack of extensions to the certificate request
    X509_REQ_add_extensions(req.get(), exts);

    // Free allocated resources
    sk_X509_EXTENSION_free(exts);
  }

  // Todo : Remove or refactor ?
  /*
  auto expdate = X509_get_notAfter(source_cert.get());
  auto startdate = X509_get_notBefore(source_cert.get());

  char expdatebuf[256];
  char startdatebuf[256];

  BIO *bio,*bio2;
  int write = 0;
  bio = BIO_new(BIO_s_mem());
  bio2 = BIO_new(BIO_s_mem());
  if (bio) {
    if (ASN1_TIME_print(bio,expdate))
      write = BIO_read(bio, expdatebuf, 255);
    BIO_free(bio);
  }
  expdatebuf[write] = '\0';
  if (bio2) {
    if (ASN1_TIME_print(bio2,startdate))
      write = BIO_read(bio2, startdatebuf, 255);
    BIO_free(bio2);
  }
  startdatebuf[write] = '\0';

  Dbg(dbg_ctl, "exp date of server cert : %s ; start date : %s", expdatebuf, startdatebuf);
  */

  /// Set Traffic Server public key
  if (X509_REQ_set_pubkey(req.get(), ca_pkey_scoped.get()) != 1) {
    TSError("[%s] mkcsr(): Failed to set pubkey.", PLUGIN_NAME);
    return nullptr;
  }
  /// Sign with Traffic Server private key
  if (X509_REQ_sign(req.get(), ca_pkey_scoped.get(), EVP_sha256()) <= 0) {
    TSError("[%s] mkcsr(): Failed to Sign.", PLUGIN_NAME);
    return nullptr;
  }
  return req;
}

/// Local helper function that generates a X509 certificate based on CSR
static scoped_X509
mkcrt(X509_REQ *req, int serial, const ASN1_TIME *expdate, const ASN1_TIME *startdate)
{
  Dbg(dbg_ctl, "Entering mkcrt()...");
  X509_NAME *subj, *tmpsubj;
  scoped_EVP_PKEY pktmp;
  scoped_X509 cert;

  cert.reset(X509_new());

  /// Set X509V3
  if (X509_set_version(cert.get(), 2) == 0) {
    TSError("[%s] mkcrt(): Failed to set X509V3.", PLUGIN_NAME);
    return nullptr;
  }

  /// Set serial number
  // Dbg("txn_monitor", "serial: %d", serial);
  ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), serial);

  /// Set issuer from CA cert
  if (X509_set_issuer_name(cert.get(), X509_get_subject_name(ca_cert_scoped.get())) == 0) {
    TSError("[%s] mkcrt(): Failed to set issuer.", PLUGIN_NAME);
    return nullptr;
  }
  /// Set certificate time
  // X509_gmtime_adj(X509_get_notBefore(cert.get()), 0);
  X509_set_notBefore(cert.get(), startdate);
  // todo: lower , configurable + add expiration handling logic
  // X509_gmtime_adj(X509_get_notAfter(cert.get()), static_cast<long>(3650) * 24 * 3600);
  if (ASN1_TIME_cmp_time_t(expdate, time(nullptr) + MAX_CERT_EXP_TIME) > 0) {
    expdate = ASN1_TIME_set(nullptr, time(nullptr) + MAX_CERT_EXP_TIME);
    X509_set_notAfter(cert.get(), expdate);
    free((void *)expdate);
    expdate = nullptr;
  } else {
    X509_set_notAfter(cert.get(), expdate);
  }
  /// Get a handle to csr subject name
  subj = X509_REQ_get_subject_name(req);
  if ((tmpsubj = X509_NAME_dup(subj)) == nullptr) {
    Dbg(dbg_ctl, "mkcrt(): Failed to duplicate subject name.");
    return nullptr;
  }
  if ((X509_set_subject_name(cert.get(), tmpsubj)) == 0) {
    Dbg(dbg_ctl, "mkcrt(): Failed to set X509 subject name");
    X509_NAME_free(tmpsubj); ///< explicit call to free X509_NAME object
    return nullptr;
  }

  int san_nid                    = NID_subject_alt_name;
  STACK_OF(X509_EXTENSION) *exts = X509_REQ_get_extensions(req);
  int num_exts                   = sk_X509_EXTENSION_num(exts);
  for (int i = 0; i < num_exts; i++) {
    X509_EXTENSION *ext = sk_X509_EXTENSION_value(exts, i);
    X509_add_ext(cert.get(), ext, -1);
  }
  sk_X509_EXTENSION_free(exts);

  pktmp.reset(X509_REQ_get_pubkey(req));
  if (pktmp == nullptr) {
    Dbg(dbg_ctl, "mkcrt(): Failed to get CSR public key.");
    X509_NAME_free(tmpsubj);
    return nullptr;
  }
  if (X509_set_pubkey(cert.get(), pktmp.get()) == 0) {
    Dbg(dbg_ctl, "mkcrt(): Failed to set X509 public key.");
    X509_NAME_free(tmpsubj);
    return nullptr;
  }

  X509_sign(cert.get(), ca_pkey_scoped.get(), EVP_sha256());

  return cert;
}

class Certifier
{
private:
  std::string _lookup;
  std::string _cert_filename;
  std::string _servername;
  TSVConn _client_vc;
  TSSslConnection _sslobj;
  SSL *_ssl;
  TSIOBuffer _buf;
  TSVConn _origin_conn;
  TSEventThread _net_thread;
  scoped_X509 _origin_cert;
  bool _delete_cert_from_disk;
  std::atomic_int _reference_count;
  TSMutex _mutex;

public:
  Certifier()
    : _lookup(""),
      _client_vc(nullptr),
      _ssl(nullptr),
      _buf(nullptr),
      _origin_conn(nullptr),
      _net_thread(nullptr),
      _delete_cert_from_disk(false),
      _reference_count(1),
      _mutex(nullptr)

  {
  }
  void
  AddReference()
  {
    int cur_rc = ++_reference_count;
    Dbg(dbg_ctl, "addref to %p:%d", this, cur_rc);
  }
  bool
  ReleaseReference()
  {
    int cur_rc = --_reference_count;
    Dbg(dbg_ctl, "releaseref to %p:%d", this, cur_rc);
    bool ret = cur_rc == 0;
    if (ret)
      delete this;
    return ret;
  }
  static int
  cont_cert_retriever(TSCont contp, TSEvent event, void *edata)
  {
    TSVConn ssl_vc         = reinterpret_cast<TSVConn>(edata);
    TSSslConnection sslobj = TSVConnSslConnectionGet(ssl_vc);
    SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
    const char *servername = SSL_get_servername(ssl, TLSEXT_NAMETYPE_host_name);

    // If the policy argument is not set, continue on
    int certifierPolicyIndex;
    if (TS_SUCCESS != TSUserArgIndexReserve(TS_USER_ARGS_VCONN, CertifierPolicyTag, "Certifier policy", &certifierPolicyIndex)) {
      TSError("Failed to register IDS policy index");
      return TS_ERROR;
    }
    void *val = TSUserArgGet(ssl_vc, certifierPolicyIndex);
    if (val == nullptr) {
      TSVConnReenable(ssl_vc);
      return TS_SUCCESS;
    }

    if (servername != nullptr && strlen(servername) > 254) {
      Dbg(dbg_ctl, "Invalid servername -- greater than 255 characters");
      TSVConnReenable(ssl_vc);
    } else {
      char lookup[300];
      SSL_CTX *ref_ctx = nullptr;

      char tempaddress[52];

      auto target = TSNetVConnLocalAddrGet(ssl_vc);
      sprintf(lookup, "[%s][%s]v2", servername ? servername : "", TSIPNPToP(target, tempaddress, 52));

      bool wontdo                = false;
      bool delete_cert_from_disk = false;
      bool lookup_scheduled      = false;
      ref_ctx                    = ssl_list->lookup_and_create(lookup, ssl_vc, wontdo, delete_cert_from_disk, lookup_scheduled);
      if (lookup_scheduled) {
        Dbg(dbg_ctl, "cert_retriever(): cert is already running for %s, connection %p is attached", lookup, ssl_vc);
      } else if (wontdo) {
        Dbg(dbg_ctl, "cert_retriever(): Won't generate cert for %s", lookup);
        TSVConnReenable(ssl_vc);
      } else if (nullptr != ref_ctx) {
        // Use existing context
        Dbg(dbg_ctl, "cert_retriever(): Reuse existing cert and context for %s", servername);
        SSL_set_SSL_CTX(ssl, ref_ctx);
        TSVConnReenable(ssl_vc);
      } else {
        auto c                    = new Certifier();
        c->_delete_cert_from_disk = delete_cert_from_disk;
        c->ScheduleRetrieveFromDisk(std::string(servername ? servername : ""), std::string(lookup), ssl_vc, sslobj, ssl);
        // If no existing context, schedule TASK thread to generate
      }
    }
    return TS_SUCCESS;
  }

  TSMutex
  GetCertifierMutex()
  {
    if (_mutex == nullptr) {
      _mutex = TSMutexCreate();
    }
    return _mutex;
  }

  int
  ScheduleRetrieveFromDisk(const std::string &servername, const std::string &lookup, TSVConn client_vc,
                           TSSslConnection client_ssl_conn, SSL *client_ssl)
  {
    Dbg(dbg_ctl, "Scheduling retrieve from disk %p %s:%s", this, servername.c_str(), lookup.c_str());
    _servername          = servername;
    _lookup              = lookup;
    _client_vc           = client_vc;
    _ssl                 = client_ssl;
    _sslobj              = client_ssl_conn;
    _net_thread          = TSEventThreadSelf();
    TSCont schedule_cont = TSContCreate(cont_retrieve_from_disk, GetCertifierMutex());

    TSContDataSet(schedule_cont, (void *)this);
    TSContScheduleOnPool(schedule_cont, 0, TS_THREAD_POOL_TASK);
    return TS_SUCCESS;
  }
  static inline Certifier *
  CertifierFromCont(TSCont contp)
  {
    return reinterpret_cast<Certifier *>(TSContDataGet(contp));
  }
  static int
  cont_retrieve_from_disk(TSCont contp, TSEvent event, void *edata)
  {
    Certifier *c = CertifierFromCont(contp);
    int ret      = TS_ERROR;
    if (c != nullptr) {
      c->AddReference();
      ret = c->handle_retrieve_from_disk();
      c->ReleaseReference();
      TSContDestroy(contp);
    }
    return ret;
  }

  int
  handle_retrieve_from_disk()
  {
    scoped_X509_REQ req;
    scoped_X509 cert;
    int ret = TS_SUCCESS;
    cert    = ReadCertFromDisk();

    if (cert != nullptr) {
      ret = ResumeConnectionsWithCert(std::move(cert));
      ReleaseReference();
    } else {
      if (!sign_enabled) {
        ResumeConnectionsWithWontDo();
        ReleaseReference();
      } else {
        ret = ScheduleProbeOrigin();
      }
    }
    return ret;
  }
  int
  ScheduleProbeOrigin()
  {
    TSCont schedule_cont = TSContCreate(cont_probe_origin, GetCertifierMutex());
    TSContDataSet(schedule_cont, (void *)this);
    TSContScheduleOnThread(schedule_cont, 0, _net_thread);
    return TS_SUCCESS;
  }
  int
  ScheduleCreateCert()
  {
    TSCont schedule_cont = TSContCreate(cont_create_cert, GetCertifierMutex());
    TSContDataSet(schedule_cont, (void *)this);
    TSContScheduleOnPool(schedule_cont, 0, TS_THREAD_POOL_TASK);
    return TS_SUCCESS;
  }

  bool
  hex_encode(const char *from_data, char *to_data, int to_len)
  {
    int i             = 0;
    int j             = 0;
    char hex_digits[] = "0123456789abcdef";
    while (from_data[i] != '\0' && j < to_len - 1) {
      if (isalnum(from_data[i])) {
        to_data[j++] = from_data[i];
      } else {
        if (j + 3 >= to_len - 1) {
          break;
        }
        to_data[j++] = '-';
        to_data[j++] = hex_digits[(from_data[i] >> 4) & 0x0f];
        to_data[j++] = hex_digits[from_data[i] & 0x0f];
      }
      i++;
    }
    to_data[j] = '\0';
    return (from_data[i] == '\0');
  }

  // Todo : change name because it can also delete cert
  scoped_X509
  ReadCertFromDisk()
  {
    scoped_X509 cert;
    /// Calculate hash and path, try certs on disk first
    unsigned char digest[MD5_DIGEST_LENGTH];
    MD5(reinterpret_cast<unsigned char const *>(_lookup.data()), _lookup.length(), digest);
    char md5String[5];
    sprintf(md5String, "%02hhx%02hhx", digest[0], digest[1]);
    std::string path = store_path + "/" + std::string(md5String, 3);
    // Todo : _lookup should be encoded here -- all the non alpha-numeric characters should be encoded
    char encoded_lookup[950];
    hex_encode(_lookup.c_str(), encoded_lookup, 950);
    std::string encoded_lookup_cstr = std::string(encoded_lookup);
    _cert_filename                  = path + '/' + encoded_lookup_cstr + ".crt";

    // if delete_cert from disk is true delete the file from disk and return an empty scopedX509

    struct stat st;
    FILE *fp = nullptr;

    int stat_retval = stat(path.c_str(), &st);

    if (this->_delete_cert_from_disk && stat_retval != -1) {
      if (std::remove(_cert_filename.c_str())) {
        Dbg(dbg_ctl, "Could not delete cert file %s", _cert_filename.c_str());
      }
      // Todo : set delete_cert to false
      Dbg(dbg_ctl, "Successfully deleted expired cert %s", _cert_filename.c_str());
      cert.reset(nullptr);
      return cert;
    }

    /// If directory doesn't exist, create one
    if (stat_retval == -1) {
      mkdir(path.c_str(), 0755);
    } else {
      /// Try open the file if directory exists
      fp = fopen(_cert_filename.c_str(), "rt");
    }
    Dbg(dbg_ctl, "shadow_cert_generator(): Cert file is expected at %s", _cert_filename.c_str());
    /// If cert file exists and is readable
    if (fp != nullptr) {
      cert.reset(PEM_read_X509(fp, nullptr, nullptr, nullptr));
      fclose(fp);

      if (cert == nullptr) {
        /// Problem with cert file / openssl read
        TSError("[%s] [shadow_cert_generator] Problem with loading certs", PLUGIN_NAME);
        std::remove(_cert_filename.c_str());
      } else {
        Dbg(dbg_ctl, "shadow_cert_generator(): Loaded cert from file");
        const ASN1_TIME *expdate_origin_cert = X509_get0_notAfter(cert.get());
        // Todo : Do we need to check begin dates here ?
        // const ASN1_TIME *startdate_origin_cert = X509_get0_notBefore(cert.get());
        // if cert is expired or expires with ASSUME_EXPIRED_TIME delete and probe origin
        if (ASN1_TIME_cmp_time_t(expdate_origin_cert, (time(nullptr) + ASSUME_EXPIRED_TIME)) < 0) {
          std::remove(_cert_filename.c_str());
          cert.reset(nullptr);
          Dbg(dbg_ctl, "Cert read from file is expired -- it will be deleted");
        }
      }
    }
    return cert;
  }
  void
  ResumeConnectionsWithWontDo()
  {
    std::queue<void *> localQ;
    // Todo: add reason in logging
    // Dbg(dbg_ctl, "shadow_cert_generator(): No certs found and dynamic generation disabled. Marked as wontdo.");
    // There won't be certs available. Mark this servername as wontdo
    // Pass on as if plugin doesn't exist

    time_t current_time = time(nullptr);

    // TODO : add an exp time here as well current time + 5 min
    ssl_list->setup_data_ctx(_lookup, localQ, nullptr, nullptr, true, current_time + RETRY_TIME, -1);
    while (!localQ.empty()) {
      // Dbg(dbg_ctl, "\tClearing the queue size %lu", localQ.size());
      TSVConn ssl_vc = reinterpret_cast<TSVConn>(localQ.front());
      Dbg(dbg_ctl, "Resuming connection %p", ssl_vc);
      localQ.pop();
      TSVConnReenable(ssl_vc);
    }
    //_deleteme=true;
  }
  scoped_X509
  CreateCert()
  {
    FILE *fp = nullptr;
    scoped_X509_REQ req;
    scoped_X509 cert;

    // Todo(move out)

    Dbg(dbg_ctl, "shadow_cert_generator(): Creating shadow certs");

    /// Get serial number
    TSMutexLock(serial_mutex);
    int serial = ca_serial++;

    /// Write to serial file with lock held
    if (serial_file) {
      serial_file.seekp(0, serial_file.beg); ///< Reset to beginning fo file
      serial_file << serial << "\n";
    }

    TSMutexUnlock(serial_mutex);

    const ASN1_TIME *expdate_origin_cert   = X509_get0_notAfter(_origin_cert.get());
    const ASN1_TIME *startdate_origin_cert = X509_get0_notBefore(_origin_cert.get());

    /*struct tm exp_tm = {0};
    struct tm begin_tm = {0};
    int ret1 = ASN1_TIME_to_tm(expdate_origin_cert, &exp_tm);
    int ret2 = ASN1_TIME_to_tm(startdate_origin_cert, &begin_tm);
    Dbg(dbg_ctl, "checking asn1 ret values %d %d %d ", ret1, ret2, exp_tm.tm_hour);
    if (ret1 && ret2) {
      this->_cert_exp_date = mktime(&exp_tm);
      this->_cert_begin_date = mktime(&begin_tm);
    }
    else {
      Dbg(dbg_ctl, "Expiration/Begin date extraction from origin cert failed");
    }*/

    /// Create CSR and cert
    req = mkcsr(_origin_cert);
    if (req == nullptr) {
      Dbg(dbg_ctl, "[shadow_cert_generator] CSR generation failed");

      ssl_list->set_schedule(_lookup, false);
      return nullptr;
    }
    cert = mkcrt(req.get(), serial, expdate_origin_cert, startdate_origin_cert);

    if (cert == nullptr) {
      Dbg(dbg_ctl, "[shadow_cert_generator] Cert generation failed");

      ssl_list->set_schedule(_lookup, false);
      return nullptr;
    }

    /// Write certs to file
    if ((fp = fopen(_cert_filename.c_str(), "w+")) == nullptr) {
      Dbg(dbg_ctl, "shadow_cert_generator(): Error opening file: %s\n", strerror(errno));
    } else {
      if (!PEM_write_X509(fp, cert.get())) {
        Dbg(dbg_ctl, "shadow_cert_generator(): Error writing cert to disk");
      }
      fclose(fp);
    }
    return cert;
  }
  int
  ResumeConnectionsWithCert(scoped_X509 cert)
  {
    SSL_CTX *ref_ctx;
    scoped_SSL_CTX ctx;
    std::queue<void *> localQ;

    // _deleteme=true;

    /// Create SSL context based on cert
    ref_ctx = SSL_CTX_new(SSLv23_server_method());
    ctx.reset(ref_ctx);
    Dbg(dbg_ctl, "%p", this);
    if (SSL_CTX_use_certificate(ref_ctx, cert.get()) < 1) {
      TSError("[%s] shadow_cert_handler(): Failed to use certificate in SSL_CTX.", PLUGIN_NAME);

      ssl_list->set_schedule(_lookup, false);
      return TS_ERROR;
    }
    Dbg(dbg_ctl, "%p", this);
    if (SSL_CTX_use_PrivateKey(ref_ctx, ca_pkey_scoped.get()) < 1) {
      TSError("[%s] shadow_cert_handler(): Failed to use private key in SSL_CTX.", PLUGIN_NAME);

      ssl_list->set_schedule(_lookup, false);
      return TS_ERROR;
    }
    Dbg(dbg_ctl, "%p", this);
    Dbg(dbg_ctl, "shadow_cert_generator(): cert and context ready, clearing the queue");
    // Todo: determine expiry for the ssl list
    // if curnt time before end date - 10 min then exp date = end date
    // else expdate = curnt time + 5min
    // times must be in UTC
    // Todo : Pull end date from cert

    const ASN1_TIME *expdate_origin_cert   = X509_get0_notAfter(cert.get());
    const ASN1_TIME *startdate_origin_cert = X509_get0_notBefore(cert.get());
    struct tm exp_tm                       = {0};
    struct tm begin_tm                     = {0};
    int ret1                               = ASN1_TIME_to_tm(expdate_origin_cert, &exp_tm);
    int ret2                               = ASN1_TIME_to_tm(startdate_origin_cert, &begin_tm);
    time_t cert_exp_date, cert_begin_date = time(nullptr);
    Dbg(dbg_ctl, "checking asn1 ret values %d %d %d ", ret1, ret2, exp_tm.tm_hour);
    if (ret1 && ret2) {
      cert_exp_date   = timegm(&exp_tm);
      cert_begin_date = timegm(&begin_tm);
    } else {
      Dbg(dbg_ctl, "Expiration/Begin date extraction from origin cert failed");
    }

    time_t current_time = time(nullptr);
    if (current_time < (cert_exp_date - ASSUME_EXPIRED_TIME)) {
      current_time = cert_exp_date;
    } else {
      // todo : make this delay configurable
      current_time = current_time + RETRY_TIME;
    }

    ssl_list->setup_data_ctx(_lookup, localQ, std::move(ctx), std::move(cert), false, current_time, cert_begin_date);
    Dbg(dbg_ctl, "%p", this);
    /// Clear the queue by setting context for each and reenable them
    while (!localQ.empty()) {
      Dbg(dbg_ctl, "\tClearing the queue size %lu", localQ.size());
      TSVConn ssl_vc = reinterpret_cast<TSVConn>(localQ.front());
      localQ.pop();
      TSSslConnection sslobj = TSVConnSslConnectionGet(ssl_vc);
      SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
      SSL_set_SSL_CTX(ssl, ref_ctx);
      TSVConnReenable(ssl_vc);
    }
    return TS_SUCCESS;
  }

  static int
  cont_probe_origin(TSCont contp, TSEvent event, void *edata)
  {
    Certifier *c = CertifierFromCont(contp);
    // TODO
    int ret           = TS_ERROR;
    bool destroy_cont = false;
    Dbg(dbg_ctl, "probe origin %d %p %p", event, edata, c);
    if (c != nullptr) {
      c->AddReference();
      ret = c->HandleProbeOrigin(contp, event, edata, destroy_cont);
      if (c->ReleaseReference() || destroy_cont) {
        TSContDestroy(contp);
      }
    }
    return ret;
  }

  int
  HandleProbeOrigin(TSCont contp, TSEvent event, void *edata, bool &destroy_cont)
  {
    destroy_cont = false;
    switch (event) {
    case TS_EVENT_IMMEDIATE: {
      TSNetConnectOptions opt;
      memset(&opt, 0, sizeof(TSNetConnectOptions));
      opt.to                 = TSNetVConnLocalAddrGet(this->_client_vc);
      opt.from               = TSNetVConnRemoteAddrGet(this->_client_vc);
      opt.use_from_port      = false;
      opt.tls                = true;
      opt.verify_origin_cert = true;
      opt.sni_host_name      = _servername.length() != 0 ? _servername.c_str() : nullptr;
      char tempbuf[2][52];
      Dbg(dbg_ctl, "from: %s to: %s", TSIPNPToP(opt.from, tempbuf[0], 52), TSIPNPToP(opt.to, tempbuf[1], 52));
      TSAction connect_action = TSNetConnectAdvanced(contp, &opt);
      return TS_SUCCESS;
    } break;
    case TS_EVENT_NET_CONNECT: {
      _origin_conn = reinterpret_cast<TSVConn>(edata);
      _buf         = TSIOBufferCreate();
      TSIOBufferWrite(_buf, "", 0);
      TSIOBufferReader reader = TSIOBufferReaderAlloc(_buf);
      TSVConnWrite(_origin_conn, contp, reader, 1);
      TSVConnReenable(_origin_conn);
    } break;
    case TS_EVENT_VCONN_WRITE_READY:
    case TS_EVENT_VCONN_WRITE_COMPLETE: {
      TSSslConnection sslobj = TSVConnSslConnectionGet(_origin_conn);
      SSL *ssl               = reinterpret_cast<SSL *>(sslobj);
      X509 *cert             = SSL_get_peer_certificate(ssl);
      if (cert) {
        this->_origin_cert.reset(cert);
        ScheduleCreateCert();
        TSVConnClose(_origin_conn);
        destroy_cont = true;
      } else {
        TSVConnClose(_origin_conn);
        ResumeConnectionsWithWontDo();
        ReleaseReference();
      }

    } break;
    case TS_EVENT_NET_CONNECT_FAILED:
    case TS_EVENT_ERROR: {
      Dbg(dbg_ctl, "Unexpected event %d", event);
      // TODO: set timeout on errored probe connections
      ResumeConnectionsWithWontDo();
      if (_origin_conn)
        TSVConnAbort(_origin_conn, 1);
      ReleaseReference();
    } break;
    default: {
      Dbg(dbg_ctl, "Unexpected event %d", event);
      // TODO: set timeout on errored probe connections
      ResumeConnectionsWithWontDo();
      if (_origin_conn)
        TSVConnAbort(_origin_conn, 1);
      ReleaseReference();
    } break;
    }
    return TS_SUCCESS;
  }
  static int
  cont_create_cert(TSCont contp, TSEvent event, void *edata)
  {
    Certifier *c = CertifierFromCont(contp);
    // TODO
    int ret = TS_ERROR;
    if (c != nullptr) {
      c->AddReference();
      ret = c->HandleCreateCert();
      TSContDestroy(contp);
      c->ReleaseReference();
    }
    return ret;
  }
  int
  HandleCreateCert()
  {
    scoped_X509_REQ req;
    scoped_X509 cert;
    int ret = TS_ERROR;
    /// Create CSR and cert
    cert = std::move(CreateCert());
    Dbg(dbg_ctl, "Cert ptr:%p", cert.get());
    if (cert != nullptr) {
      ret = this->ResumeConnectionsWithCert(std::move(cert));
    } else {
      this->ResumeConnectionsWithWontDo();
    }
    // req = mkcsr_from_cert(_origin_cert);
    Dbg(dbg_ctl, "Cert ptr:%p", cert.get());
    ReleaseReference();
    return ret;
  }

  // void
  // ExtractDatesFromCert()
};

void
TSPluginInit(int argc, const char *argv[])
{
  Dbg(dbg_ctl, "initializing plugin");
  Dbg(dbg_ctl, "OpenSSL version %s", OpenSSL_version(OPENSSL_VERSION));
  Dbg(dbg_ctl, "OpenSSL built on %s", OpenSSL_version(OPENSSL_BUILT_ON));

  // Initialization data and callback
  TSPluginRegistrationInfo info;
  TSCont cb_shadow   = nullptr;
  info.plugin_name   = "avx_certifier";
  info.vendor_name   = "Aviatrix";
  info.support_email = "info@aviatrix.com";

  const char *key    = nullptr;
  const char *cert   = nullptr;
  const char *serial = nullptr;

  // Read options from plugin.config
  static const struct option longopts[] = {
    {"sign-cert",   required_argument, nullptr, 'c'},
    {"sign-key",    required_argument, nullptr, 'k'},
    {"sign-serial", required_argument, nullptr, 'r'},
    {"max",         required_argument, nullptr, 'm'},
    {"store",       required_argument, nullptr, 's'},
    {nullptr,       no_argument,       nullptr, 0  }
  };

  int opt = 0;

  while (opt >= 0) {
    opt = getopt_long(argc, const_cast<char *const *>(argv), "c:k:r:m:s:", longopts, nullptr);
    switch (opt) {
    case 'c': {
      cert = optarg;
      break;
    }
    case 'k': {
      key = optarg;
      break;
    }
    case 'r': {
      serial = optarg;
      break;
    }
    case 'm': {
      ssl_list.reset(new SslLRUList(static_cast<int>(std::strtol(optarg, nullptr, 0))));
      break;
    }
    case 's': {
      store_path = std::string(optarg);
      break;
    }
    case -1:
    case '?':
      break;
    default:
      Dbg(dbg_ctl, "Unexpected options.");
      TSError("[%s] Unexpected options error.", PLUGIN_NAME);
      return;
    }
  }

  // Register plugin and create callback
  if (TSPluginRegister(&info) != TS_SUCCESS) {
    TSError("[%s] Unable to initialize plugin (disabled). Failed to register plugin.", PLUGIN_NAME);
  } else if ((cb_shadow = TSContCreate(Certifier::cont_cert_retriever, nullptr)) == nullptr) {
    TSError("[%s] Unable to initialize plugin (disabled). Failed to create shadow cert cb.", PLUGIN_NAME);
  } else {
    if ((sign_enabled = cert && key && serial)) {
      // Dynamic cert generation enabled. Initialize CA key, cert and serial
      // To comply to openssl, key and cert file are opened as FILE*
      FILE *fp = nullptr;
      if ((fp = fopen(cert, "rt")) == nullptr) {
        Dbg(dbg_ctl, "fopen() error is %d: %s for %s", errno, strerror(errno), cert);
        TSError("[%s] Unable to initialize plugin. Failed to open ca cert.", PLUGIN_NAME);
        return;
      }
      ca_cert_scoped.reset(PEM_read_X509(fp, nullptr, nullptr, nullptr));
      fclose(fp);

      if ((fp = fopen(key, "rt")) == nullptr) {
        Dbg(dbg_ctl, "fopen() error is %d: %s for %s", errno, strerror(errno), key);
        TSError("[%s] Unable to initialize plugin. Failed to open ca key.", PLUGIN_NAME);
        return;
      }
      ca_pkey_scoped.reset(PEM_read_PrivateKey(fp, nullptr, nullptr, nullptr));
      fclose(fp);

      if (ca_pkey_scoped == nullptr || ca_cert_scoped == nullptr) {
        Dbg(dbg_ctl, "PEM_read failed to read %s %s", ca_pkey_scoped ? "" : "pkey", ca_cert_scoped ? "" : "cert");
        TSError("[%s] Unable to initialize plugin. Failed to read ca key/cert.", PLUGIN_NAME);
        return;
      }

      // Read serial file
      serial_file.open(serial, std::fstream::in | std::fstream::out);
      if (!serial_file.is_open()) {
        Dbg(dbg_ctl, "Failed to open serial file.");
        TSError("[%s] Unable to initialize plugin. Failed to open serial.", PLUGIN_NAME);
        return;
      }
      /// Initialize mutex and serial number
      serial_mutex = TSMutexCreate();
      ca_serial    = 0;

      serial_file.seekg(0, serial_file.beg);
      serial_file >> ca_serial;
      if (serial_file.bad() || serial_file.fail()) {
        ca_serial = 0;
      }
    }
    Dbg(dbg_ctl, "Dynamic cert generation %s", sign_enabled ? "enabled" : "disabled");

    /// Add global hooks
    TSHttpHookAdd(TS_SSL_CERT_HOOK, cb_shadow);
  }

  return;
}
