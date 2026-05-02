#include <thread>
#include <atomic>
#include <ctime>
#include <utility>        
#include <boost/asio.hpp> 
#include <signal.h>
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if.h> 
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <cstdint>
#include <map>
#include <iomanip>
#include <iterator>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/hmac.h>
#include <array>
#include <shared_mutex>
#include <sys/epoll.h>
#include <span>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
#include <openssl/objects.h>
#include <oqs/oqs.h>
#include <oqs/kem.h>

constexpr size_t MLKEM768_PKEY_LEN = 1184;
constexpr size_t MLKEM768_SS_LEN = 32;
#define PORT 62000
#define KEYPORT 61000
#define MAXLINE 20480
#define AES_GCM_KEY_LEN 32
#define AES_GCM_IV_LEN 12
#define TAG_SIZE 16

#define HQC_256_PK_LEN      7245
#define HQC_256_SK_LEN      7317
#define HQC_256_CT_LEN      14421
#define HQC_256_SS_LEN      64

#define VALIDATE_CERT "server.crt"
#define SERVER_CA_CERT "ca.crt"

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

using std::string;

#include "assert.h"
#include <mutex>
#include <vector>

std::string to_hex_snippet(const std::vector<uint8_t> &data, size_t len = 32);

std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);
std::vector<uint8_t> sha3_512(const std::vector<uint8_t> &data);

string xy_str;
string kyber_cipher_data_str;
string qkd_parameter;

void send_framed_message(tcp::socket &socket, const std::string &msg)
{
    uint32_t msg_len = htonl(static_cast<uint32_t>(msg.length()));
    std::array<boost::asio::const_buffer, 2> bufs = {
        boost::asio::buffer(&msg_len, sizeof(msg_len)),
        boost::asio::buffer(msg)
    };
    boost::asio::write(socket, bufs);
}

std::string receive_framed_message(tcp::socket &socket)
{
    uint32_t msg_len;
    boost::system::error_code ec;
    boost::asio::read(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)), ec);
    if (ec)
    {
        throw boost::system::system_error(ec);
    }
    msg_len = ntohl(msg_len);

    if (msg_len > MAXLINE)
    { // Sanity check
        throw std::runtime_error("Received message length exceeds maximum.");
    }

    std::vector<char> msg_buf(msg_len);
    boost::asio::read(socket, boost::asio::buffer(msg_buf));
    return std::string(msg_buf.begin(), msg_buf.end());
}

void cert_authenticate_online(const char *srv_ip)
{
    SSL_CTX *ctx;
    SSL *ssl;
    BIO *bio;

    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        printf("Error while creating context.\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, SERVER_CA_CERT, NULL) != 1)
    {
        printf("Error while loading a server CA certificate.\n");
        exit(EXIT_FAILURE);
    }

    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("Error while creating SSL connection.\n");
        exit(EXIT_FAILURE);
    }

    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL)
    {
        printf("Error while creating BIO object.\n");
        exit(EXIT_FAILURE);
    }

    string hostname = srv_ip + string(":") + string("61000");
    BIO_set_conn_hostname(bio, hostname.c_str());

    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    if (BIO_do_connect(bio) <= 0)
    {
        printf("Connection error.\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_get_verify_result(ssl) != X509_V_OK)
    {
        printf("Error while verifying the certificate.\n");
        printf("Error: %s\n", X509_verify_cert_error_string(SSL_get_verify_result(ssl)));
        exit(EXIT_FAILURE);
    }

    BIO_free_all(bio);
    SSL_CTX_free(ctx);
}

void cert_authenticate_offline()
{

    X509 *serverCert = NULL;
    X509 *caCert = NULL;
    X509_STORE *store = NULL;
    X509_STORE_CTX *ctx = NULL;

    FILE *file = fopen(VALIDATE_CERT, "r");
    if (!file)
    {
        perror("Error opening server certificate file");
        exit(EXIT_FAILURE);
    }
    serverCert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    if (!serverCert)
    {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }

    file = fopen(SERVER_CA_CERT, "r");
    if (!file)
    {
        perror("Error opening CA certificate file");
        X509_free(serverCert);
        exit(EXIT_FAILURE);
    }
    caCert = PEM_read_X509(file, NULL, NULL, NULL);
    fclose(file);
    if (!caCert)
    {
        ERR_print_errors_fp(stderr);
        X509_free(serverCert);
        exit(EXIT_FAILURE);
    }

    store = X509_STORE_new();
    if (!store || X509_STORE_add_cert(store, caCert) != 1)
    {
        perror("Error adding CA certificate to store");
        X509_free(serverCert);
        X509_free(caCert);
        X509_STORE_free(store);
        exit(EXIT_FAILURE);
    }

    ctx = X509_STORE_CTX_new();
    if (!ctx || X509_STORE_CTX_init(ctx, store, serverCert, NULL) != 1)
    {
        perror("Error initializing X509_STORE_CTX");
        X509_free(serverCert);
        X509_free(caCert);
        X509_STORE_CTX_free(ctx);
        X509_STORE_free(store);
        exit(EXIT_FAILURE);
    }

    if (X509_verify_cert(ctx) != 1)
    {
        if (X509_STORE_CTX_get_error(ctx) == X509_V_ERR_DEPTH_ZERO_SELF_SIGNED_CERT)
        {
            printf("Certificate is self-signed\n");
            return;
        }
        else
        {
            perror("Certificate verification failed");
            perror(X509_verify_cert_error_string(X509_STORE_CTX_get_error(ctx)));
            X509_free(serverCert);
            X509_free(caCert);
            X509_STORE_CTX_free(ctx);
            X509_STORE_free(store);
            exit(EXIT_FAILURE);
        }
    }

    X509_free(serverCert);
    X509_free(caCert);
    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
}

string convertToString(char *a)
{
    string s = a;
    return s;
}

int tun_open()
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) == -1)
    {
        perror("open /dev/net/tun");
        throw std::runtime_error("Failed to open /dev/net/tun");
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) == -1)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        throw std::runtime_error("ioctl(TUNSETIFF) failed for tun0");
    }

    return fd;
}

string data_recieve(udp::socket &socket, udp::endpoint &remote_endpoint)
{
    char buffer[MAXLINE];
    boost::system::error_code error;
    size_t n = socket.receive_from(boost::asio::buffer(buffer), remote_endpoint, 0, error);
    if (error && error != boost::asio::error::message_size)
        return "";
    return string(buffer, n);
}

const std::string keepalive_msg_from_server = "KEEPALIVE_S";

bool is_keepalive_from_server(const std::string &msg)
{
    return msg == keepalive_msg_from_server;
}

string read_tun(int tundesc)
{
    char buf[MAXLINE - 60];
    int nbytes = read(tundesc, buf, sizeof(buf));
    if (nbytes <= 0)
        return "";
    return string(buf, nbytes);
}

/* Virtual interface data write.
   Data will appear as if it arrived at
   virtual interface and can be routed further */

void write_tun(int tundesc, const string &message)
{
    write(tundesc, message.data(), message.length());
}

void send_encrypted(udp::socket &socket, udp::endpoint &remote_endpoint, const string &cipher)
{
    socket.send_to(boost::asio::buffer(cipher), remote_endpoint);
}

string encrypt_data(EVP_CIPHER_CTX *ctx, const std::vector<unsigned char> &key, const string &plaintext)
{
    // Single pre-allocated output: [IV(12)][ciphertext(N)][tag(16)]
    string result(AES_GCM_IV_LEN + plaintext.length() + TAG_SIZE, '\0');
    unsigned char *const buf     = reinterpret_cast<unsigned char *>(result.data());
    unsigned char *const iv_ptr  = buf;
    unsigned char *const ct_ptr  = buf + AES_GCM_IV_LEN;
    unsigned char *const tag_ptr = buf + AES_GCM_IV_LEN + plaintext.length();

    if (RAND_bytes(iv_ptr, AES_GCM_IV_LEN) != 1)
        return "";
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv_ptr) != 1)
        return "";

    int len = 0, ct_len = 0;
    if (EVP_EncryptUpdate(ctx, ct_ptr, &len,
                          reinterpret_cast<const unsigned char *>(plaintext.data()),
                          static_cast<int>(plaintext.length())) != 1)
        return "";
    ct_len = len;

    if (EVP_EncryptFinal_ex(ctx, ct_ptr + ct_len, &len) != 1)
        return "";
    ct_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag_ptr) != 1)
        return "";

    result.resize(AES_GCM_IV_LEN + ct_len + TAG_SIZE);
    return result;
}

string decrypt_data(EVP_CIPHER_CTX *ctx, const std::vector<unsigned char> &key, const string &cipher_with_iv_tag)
{
    if (cipher_with_iv_tag.length() < AES_GCM_IV_LEN + TAG_SIZE)
        return "";

    const unsigned char *iv         = reinterpret_cast<const unsigned char *>(cipher_with_iv_tag.data());
    const unsigned char *ciphertext = iv + AES_GCM_IV_LEN;
    const size_t ct_len             = cipher_with_iv_tag.length() - AES_GCM_IV_LEN - TAG_SIZE;
    const unsigned char *tag        = ciphertext + ct_len;

    // Write plaintext directly into a pre-sized string
    string plaintext(ct_len, '\0');
    unsigned char *pt_ptr = reinterpret_cast<unsigned char *>(plaintext.data());

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv) != 1)
        return "";

    int len = 0;
    if (EVP_DecryptUpdate(ctx, pt_ptr, &len, ciphertext, static_cast<int>(ct_len)) != 1)
        return "";
    int pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE,
                             const_cast<unsigned char *>(tag)) != 1)
        return "";

    int ret = EVP_DecryptFinal_ex(ctx, pt_ptr + pt_len, &len);
    if (ret > 0)
    {
        pt_len += len;
        plaintext.resize(pt_len);
        return plaintext;
    }
    return "";
}

/*
   Reads from TUN, encrypts in-place, and sends over UDP.
   buf must be at least AES_GCM_IV_LEN + MAXLINE + TAG_SIZE bytes.
   Returns false when the TUN has no more data (EAGAIN).
*/
bool E_N_C_R(EVP_CIPHER_CTX *enc_ctx, udp::socket &socket, udp::endpoint &remote_endpoint,
             const std::vector<unsigned char> &key, int tundesc, uint8_t *buf)
{
    // Layout: [IV(12)] [plaintext→ciphertext(n)] [tag(16)]
    uint8_t *iv  = buf;
    uint8_t *msg = buf + AES_GCM_IV_LEN;

    int n = ::read(tundesc, msg, MAXLINE - 60);
    if (n <= 0)
        return false;

    if (RAND_bytes(iv, AES_GCM_IV_LEN) != 1)
        return false;

    if (EVP_EncryptInit_ex(enc_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(enc_ctx, NULL, NULL, key.data(), iv) != 1)
        return false;

    int len = 0, ct_len = 0;
    if (EVP_EncryptUpdate(enc_ctx, msg, &len, msg, n) != 1)  // in-place
        return false;
    ct_len = len;
    if (EVP_EncryptFinal_ex(enc_ctx, msg + ct_len, &len) != 1)
        return false;
    ct_len += len;

    uint8_t *tag = msg + ct_len;
    if (EVP_CIPHER_CTX_ctrl(enc_ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag) != 1)
        return false;

    boost::system::error_code send_ec;
    socket.send_to(boost::asio::buffer(buf, AES_GCM_IV_LEN + ct_len + TAG_SIZE),
                   remote_endpoint, 0, send_ec);
    return true;
}

/*
   Receives from UDP, decrypts in-place, and writes to TUN.
   buf must be at least MAXLINE bytes.
   Returns false when the socket has no more data (EAGAIN).
*/
bool D_E_C_R(EVP_CIPHER_CTX *dec_ctx, udp::socket &socket, udp::endpoint &remote_endpoint,
             const std::vector<unsigned char> &key, int tundesc, uint8_t *buf)
{
    boost::system::error_code error;
    size_t n = socket.receive_from(boost::asio::buffer(buf, MAXLINE), remote_endpoint, 0, error);
    if (error && error != boost::asio::error::message_size)
        return false;
    if (n == 0)
        return false;

    if (n == keepalive_msg_from_server.size() &&
        memcmp(buf, keepalive_msg_from_server.data(), n) == 0)
        return false;

    if (n < static_cast<size_t>(AES_GCM_IV_LEN + TAG_SIZE + 1))
        return false;

    uint8_t *iv    = buf;
    uint8_t *ct    = buf + AES_GCM_IV_LEN;
    size_t   ct_len = n - AES_GCM_IV_LEN - TAG_SIZE;
    uint8_t *tag   = ct + ct_len;

    if (EVP_DecryptInit_ex(dec_ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL) != 1 ||
        EVP_DecryptInit_ex(dec_ctx, NULL, NULL, key.data(), iv) != 1)
        return false;

    int len = 0;
    if (EVP_DecryptUpdate(dec_ctx, ct, &len, ct, static_cast<int>(ct_len)) != 1)  // in-place
        return false;
    int pt_len = len;

    if (EVP_CIPHER_CTX_ctrl(dec_ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, tag) != 1)
        return false;

    if (EVP_DecryptFinal_ex(dec_ctx, ct + pt_len, &len) <= 0)
        return false;
    pt_len += len;

    ::write(tundesc, ct, pt_len);
    return true;
}

std::string to_hex(const std::vector<uint8_t> &data)
{
    std::stringstream ss;

    ss << std::hex << std::uppercase << std::setfill('0');

    for (uint8_t byte : data)
    {
        ss << std::setw(2) << (int)byte;
    }

    return ss.str();
}

std::string to_hex_snippet(const std::vector<uint8_t> &data, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');

    size_t count = std::min(data.size(), len);
    for (size_t i = 0; i < count; ++i)
    {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    if (data.size() > len)
    {
        ss << "...";
    }
    return ss.str();
}

inline std::string to_hex(const unsigned char *data, size_t len)
{
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (size_t i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<int>(data[i]);
    return ss.str();
}

std::vector<uint8_t> hex_to_bytes(const std::string &hex)
{
    if (hex.length() % 2 != 0)
    {
        throw std::invalid_argument("Hex string must have an even length.");
    }

    std::vector<uint8_t> bytes;
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2)
    {

        std::string byteString = hex.substr(i, 2);

        long value = std::strtol(byteString.c_str(), nullptr, 16);

        bytes.push_back(static_cast<uint8_t>(value));
    }

    return bytes;
}

std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data)
{
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                          key.data(), key.size());
    if (!pkey)
        return {};

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        return {};
    }

    std::vector<uint8_t> digest;
    size_t digest_len = 0;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha512(), nullptr, pkey) <= 0 ||
        EVP_DigestSignUpdate(ctx, data.data(), data.size()) <= 0 ||
        EVP_DigestSignFinal(ctx, NULL, &digest_len) <= 0) // First call to get length
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return {};
    }

    digest.resize(digest_len);
    if (EVP_DigestSignFinal(ctx, digest.data(), &digest_len) <= 0) // Second call to get data
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return {};
    }
    digest.resize(digest_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return digest;
}

std::vector<uint8_t> sha3_512(const std::vector<uint8_t> &data)
{
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return {};

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr);
    EVP_DigestUpdate(mdctx, data.data(), data.size());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    return std::vector<uint8_t>(md_value, md_value + md_len);
}

std::vector<uint8_t> xorVectors(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    size_t n = std::min(a.size(), b.size());
    std::vector<uint8_t> result(n);
    for (size_t i = 0; i < n; i++)
        result[i] = a[i] ^ b[i];
    return result;
}

EVP_PKEY *create_pqc_pubkey_from_raw(const std::string &alg_name, const std::vector<uint8_t> &raw_pkey)
{
    EVP_PKEY *pkey = EVP_PKEY_new_raw_public_key_ex(
        /*libctx=*/NULL,
        alg_name.c_str(),
        /*propq=*/NULL,
        raw_pkey.data(),
        raw_pkey.size());
    if (!pkey)
    {
        std::cerr << "Error: EVP_PKEY_new_raw_public_key_ex failed.\n";
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    return pkey;
}

// Helper: List available OQS KEM algorithms
void list_available_kem_algorithms()
{
    std::cout << "\nAvailable OQS KEM algorithms:\n";
    int count = OQS_KEM_alg_count();
    for (int i = 0; i < count; i++)
    {
        const char *alg = OQS_KEM_alg_identifier(i);
        if (alg && OQS_KEM_alg_is_enabled(alg))
        {
            std::cout << "  - " << alg << "\n";
        }
    }
    std::cout << "\n";
}

// Generate HQC-256 keypair using direct OQS API (runtime interface)
std::pair<std::vector<uint8_t>, std::vector<uint8_t>> generate_pqc_keypair_hqc()
{
    OQS_KEM *kem = OQS_KEM_new("HQC-256");
    if (kem == NULL)
    {
        std::cerr << "generate_pqc_keypair_hqc: OQS_KEM_new failed for HQC-256\n";
        std::cerr << "HQC-256 may not be enabled in liboqs. ";
        list_available_kem_algorithms();
        return {{}, {}};
    }

    std::vector<uint8_t> pubkey(kem->length_public_key);
    std::vector<uint8_t> privkey(kem->length_secret_key);

    OQS_STATUS status = kem->keypair(pubkey.data(), privkey.data());
    OQS_KEM_free(kem);
    
    if (status != OQS_SUCCESS)
    {
        std::cerr << "generate_pqc_keypair_hqc: keypair generation failed\n";
        return {{}, {}};
    }

    return {pubkey, privkey};
}

struct PQCKeyMaterial
{
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> ciphertext;
};

struct ECDHKeyMaterial
{
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> own_pubkey;
    std::vector<uint8_t> peer_pubkey;
};

struct PQC_Alg_Properties
{
    size_t shared_secret_len = 0;
    size_t pubkey_len = 0;
    size_t ciphertext_len = 0;
};

PQC_Alg_Properties get_pqc_alg_properties(const std::string & /*alg_name_ignored*/)
{
    const char *alg = "ML-KEM-768";
    PQC_Alg_Properties props{};

    EVP_KEM *kem = EVP_KEM_fetch(NULL, alg, NULL);
    if (!kem)
    {
        std::cerr << "EVP_KEM_fetch failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("KEM not present for: " + std::string(alg));
    }
    EVP_KEM_free(kem);

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    if (!pkey)
    {
        std::cerr << "EVP_PKEY_Q_keygen failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to keygen for: " + std::string(alg));
    }

    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(
            pkey,
            OSSL_PKEY_PARAM_PUB_KEY,
            NULL, 0, &pub_len) != 1 ||
        pub_len == 0)
    {
        std::cerr << "Failed to query pubkey length for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to get pubkey_len for: " + std::string(alg));
    }

    std::vector<unsigned char> pubraw(pub_len);
    if (EVP_PKEY_get_octet_string_param(
            pkey,
            OSSL_PKEY_PARAM_PUB_KEY,
            pubraw.data(), pubraw.size(), &pub_len) != 1)
    {
        std::cerr << "Failed to export pubkey for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to export pubkey for: " + std::string(alg));
    }
    props.pubkey_len = pub_len;

    EVP_PKEY_CTX *ctx_enc = EVP_PKEY_CTX_new_from_pkey(NULL, pkey, NULL);
    if (!ctx_enc)
    {
        std::cerr << "EVP_PKEY_CTX_new_from_pkey failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Failed to create encap ctx for: " + std::string(alg));
    }

    if (EVP_PKEY_encapsulate_init(ctx_enc, NULL) != 1)
    {
        std::cerr << "EVP_PKEY_encapsulate_init failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_enc);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encapsulate_init failed for: " + std::string(alg));
    }

    size_t ct_len = 0, ss_len = 0;
    if (EVP_PKEY_encapsulate(ctx_enc, NULL, &ct_len, NULL, &ss_len) != 1)
    {
        std::cerr << "EVP_PKEY_encapsulate length query failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_enc);
        EVP_PKEY_free(pkey);
        throw std::runtime_error("Encapsulate length query failed for: " + std::string(alg));
    }

    props.ciphertext_len = ct_len;
    props.shared_secret_len = ss_len;

    EVP_PKEY_CTX_free(ctx_enc);
    EVP_PKEY_free(pkey);

    return props;
}

PQCKeyMaterial get_pqckey(tcp::socket &client_socket, const std::string &alg_name)
{
    std::string server_pub_str = receive_framed_message(client_socket);
    std::vector<uint8_t> server_pub_bytes(server_pub_str.begin(), server_pub_str.end());
    std::cout << "Client: received PQC public key (len=" << server_pub_bytes.size() << ")\n";
    std::cout << "Client DEBUG: received pubkey(hex) = " << to_hex(server_pub_bytes) << "\n";

    EVP_PKEY *server_pqc_pubkey = create_pqc_pubkey_from_raw(alg_name, server_pub_bytes);
    if (!server_pqc_pubkey)
    {
        return {};
    }

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, server_pqc_pubkey, NULL);
    if (!ctx || EVP_PKEY_encapsulate_init(ctx, NULL) != 1)
    {
        std::cerr << "Error: EVP_PKEY_encapsulate_init failed.\n";
        ERR_print_errors_fp(stderr);
        if (ctx)
            EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(server_pqc_pubkey);
        return {};
    }

    size_t ciphertext_len = 0;
    size_t shared_secret_len = 0;
    if (EVP_PKEY_encapsulate(ctx, NULL, &ciphertext_len, NULL, &shared_secret_len) != 1)
    {
        std::cerr << "Error: EVP_PKEY_encapsulate (for length) failed.\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(server_pqc_pubkey);
        return {};
    }

    std::vector<uint8_t> ciphertext(ciphertext_len);
    std::vector<uint8_t> shared_secret(shared_secret_len);

    if (EVP_PKEY_encapsulate(ctx, ciphertext.data(), &ciphertext_len, shared_secret.data(), &shared_secret_len) != 1)
    {
        std::cerr << "Error: EVP_PKEY_encapsulate failed.\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(server_pqc_pubkey);
        return {};
    }
    ciphertext.resize(ciphertext_len);
    shared_secret.resize(shared_secret_len);
    EVP_PKEY_CTX_free(ctx);

    send_framed_message(client_socket, std::string(ciphertext.begin(), ciphertext.end()));

    EVP_PKEY_free(server_pqc_pubkey);
    return {shared_secret, ciphertext};
}

// HQC-256 key exchange: Perform encapsulation with server's public key
PQCKeyMaterial get_pqckey_hqc(tcp::socket &client_socket)
{
    std::string server_pub_str = receive_framed_message(client_socket);
    std::vector<uint8_t> server_pubkey(server_pub_str.begin(), server_pub_str.end());
    
    std::cout << "Client: received HQC-256 public key (len=" << server_pubkey.size() << ")\n";

    OQS_KEM *kem = OQS_KEM_new("HQC-256");
    if (kem == NULL)
    {
        std::cerr << "Error: OQS_KEM_new failed for HQC-256.\n";
        return {};
    }

    if (server_pubkey.size() != kem->length_public_key)
    {
        std::cerr << "Error: Expected HQC-256 pubkey length " << kem->length_public_key 
                  << " but got " << server_pubkey.size() << "\n";
        OQS_KEM_free(kem);
        return {};
    }
    std::cout << "Client DEBUG: received HQC-256 pubkey(hex) = " << to_hex_snippet(server_pubkey) << "\n";

    std::vector<uint8_t> ciphertext(kem->length_ciphertext);
    std::vector<uint8_t> shared_secret(kem->length_shared_secret);

    OQS_STATUS status = kem->encaps(ciphertext.data(), shared_secret.data(), server_pubkey.data());
    OQS_KEM_free(kem);
    
    if (status != OQS_SUCCESS)
    {
        std::cerr << "Error: HQC-256 encapsulation failed.\n";
        return {};
    }

    std::cout << "Client DEBUG: HQC-256 shared secret(hex) = " << to_hex(shared_secret) << "\n";
    std::cout << "Client DEBUG: HQC-256 ciphertext(hex) = " << to_hex_snippet(ciphertext) << "\n";

    try
    {
        send_framed_message(client_socket, std::string(ciphertext.begin(), ciphertext.end()));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to send HQC-256 ciphertext: " << e.what() << "\n";
        return {};
    }

    return {shared_secret, ciphertext};
}

void help()
{
    cout << endl
         << "   Usage:" << endl
         << endl;
    cout << "   ./encryptor_client  [Server IP] [QKD IP]" << endl;
    cout << "   Server IP - IP address of server gateway {x.x.x.x}" << endl;
    cout << "   QKD IP - Local QKD system IP address {x.x.x.x} (optional)" << endl
         << endl;
}

ECDHKeyMaterial PerformECDHKeyExchange(tcp::socket &sock)
{
    EVP_PKEY *client_key = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY *peer_key = nullptr;
    unsigned char *shared_secret = nullptr;
    size_t shared_secret_len = 0;
    std::vector<uint8_t> final_shared_secret_bytes;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx ||
        EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1) <= 0 ||
        EVP_PKEY_keygen(pctx, &client_key) <= 0)
    {
        std::cerr << "Error: Failed to generate client ECDH key." << std::endl;
        ERR_print_errors_fp(stderr);
        if (pctx)
            EVP_PKEY_CTX_free(pctx);
        return {};
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = nullptr;

    size_t client_pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(client_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &client_pub_len) != 1)
    {
        std::cerr << "Error: EVP_PKEY_get_octet_string_param (len) failed for client pubkey." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        return {};
    }
    std::vector<unsigned char> client_pub(client_pub_len);
    if (EVP_PKEY_get_octet_string_param(client_key, OSSL_PKEY_PARAM_PUB_KEY,
                                        client_pub.data(), client_pub.size(), &client_pub_len) != 1)
    {
        std::cerr << "Error: EVP_PKEY_get_octet_string_param (export) failed for client pubkey." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        return {};
    }

    std::cout << "Client DEBUG: sending ECDH pub len=" << client_pub.size() << std::endl;
    if (!client_pub.empty())
    {
        std::cout << "Client DEBUG: client_pub[0]=0x" << std::hex << std::uppercase << (int)client_pub[0]
                  << std::dec << " (expect 0x04)\n";
        size_t dump = std::min<size_t>(32, client_pub.size());
        std::vector<uint8_t> snippet(client_pub.begin(), client_pub.begin() + dump);
        std::cout << "Client DEBUG: client_pub snippet(hex) = " << to_hex(snippet) << std::endl;
    }

    try
    {
        send_framed_message(sock, std::string(client_pub.begin(), client_pub.end()));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to send client's public key: " << e.what() << std::endl;
        EVP_PKEY_free(client_key);
        return {};
    }

    std::string server_pub_str;
    try
    {
        server_pub_str = receive_framed_message(sock);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to receive server's public key: " << e.what() << std::endl;
        EVP_PKEY_free(client_key);
        return {};
    }
    std::vector<unsigned char> server_pub(server_pub_str.begin(), server_pub_str.end());
    std::cout << "Client DEBUG: received server_pub len=" << server_pub.size() << std::endl;
    if (!server_pub.empty())
    {
        std::cout << "Client DEBUG: server_pub[0]=0x" << std::hex << std::uppercase << (int)server_pub[0]
                  << std::dec << " (expect 0x04)\n";
        size_t dump = std::min<size_t>(32, server_pub.size());
        std::vector<uint8_t> snippet(server_pub.begin(), server_pub.begin() + dump);
        std::cout << "Client DEBUG: server_pub snippet(hex) = " << to_hex(snippet) << std::endl;
    }

    const size_t expected_len = 1 + 2 * ((521 + 7) / 8); // 133
    if (server_pub.size() != expected_len)
    {
        std::cerr << "Error: Unexpected server public key length: got " << server_pub.size()
                  << " expected " << expected_len << std::endl;
        EVP_PKEY_free(client_key);
        return {};
    }

    EVP_PKEY_CTX *fromctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!fromctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_name(NULL, \"EC\", NULL) failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        return {};
    }
    if (EVP_PKEY_fromdata_init(fromctx) != 1)
    {
        std::cerr << "Error: EVP_PKEY_fromdata_init failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(fromctx);
        EVP_PKEY_free(client_key);
        return {};
    }

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string("group", const_cast<char *>("secp521r1"), 0);
    params[1] = OSSL_PARAM_construct_octet_string(OSSL_PKEY_PARAM_PUB_KEY,
                                                  const_cast<unsigned char *>(server_pub.data()),
                                                  server_pub.size());
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(fromctx, &peer_key, EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        std::cerr << "Error: EVP_PKEY_fromdata failed to import server public key\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(fromctx);
        EVP_PKEY_free(client_key);
        return {};
    }
    EVP_PKEY_CTX_free(fromctx);

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, client_key, NULL);
    if (!dctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_pkey for derive failed." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return {};
    }

    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_derive_init or set_peer failed.\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return {};
    }

    if (EVP_PKEY_derive(dctx, NULL, &shared_secret_len) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_derive (len) failed.\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return {};
    }

    shared_secret = (unsigned char *)OPENSSL_malloc(shared_secret_len);
    if (!shared_secret)
    {
        std::cerr << "Error: OPENSSL_malloc failed\n";
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return {};
    }

    if (EVP_PKEY_derive(dctx, shared_secret, &shared_secret_len) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_derive failed\n";
        ERR_print_errors_fp(stderr);
        OPENSSL_free(shared_secret);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return {};
    }

    final_shared_secret_bytes.assign(shared_secret, shared_secret + shared_secret_len);

    OPENSSL_free(shared_secret);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(client_key);

    return {final_shared_secret_bytes, client_pub, server_pub};
}

string xorStrings(const string &str1, const string &str2)
{
    std::vector<uint8_t> bytes1 = hex_to_bytes(str1);
    std::vector<uint8_t> bytes2 = hex_to_bytes(str2);

    size_t len = std::min(bytes1.size(), bytes2.size());
    std::vector<uint8_t> result_bytes;
    result_bytes.reserve(len);

    for (size_t i = 0; i < len; ++i)
    {
        result_bytes.push_back(bytes1[i] ^ bytes2[i]);
    }

    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : result_bytes)
    {
        ss << std::setw(2) << (int)byte;
    }
    return ss.str();
}

string xorStrings_raw(const string &str1, const string &str2)
{
    string result;
    size_t len = std::min(str1.length(), str2.length());
    result.reserve(len);
    for (std::size_t i = 0; i < len; ++i)
    {
        result += static_cast<char>(str1[i] ^ str2[i]);
    }

    return result;
}

string get_qkdkey(string qkd_ip, tcp::socket &client_socket)
{
    system(("./sym-ExpQKD 'client' " + qkd_ip).c_str());

    std::ifstream t("key");
    std::stringstream buffer;
    buffer << t.rdbuf();
    string buffer_str = buffer.str();

    std::ifstream s("keyID");
    std::stringstream bufferTCP;
    bufferTCP << s.rdbuf();
    string bufferTCP_str = bufferTCP.str();
    cout << "KeyID: " << bufferTCP_str << endl;

   
    std::vector<unsigned char> shake_output(216);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
    {
        return "";
    }

    const EVP_MD *shake128 = EVP_shake128();
    EVP_DigestInit_ex(mdctx, shake128, NULL);
    EVP_DigestUpdate(mdctx, bufferTCP.str().c_str(), bufferTCP.str().length());
    EVP_DigestFinalXOF(mdctx, shake_output.data(), shake_output.size());
    EVP_MD_CTX_free(mdctx);

    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : shake_output)
    {
        ss << std::setw(2) << (int)byte;
    }
    string pom_param = ss.str();

    qkd_parameter = pom_param + bufferTCP_str.substr(0, 216);

    boost::asio::write(client_socket, boost::asio::buffer(bufferTCP_str));
    cout << "QKD key established:" << buffer_str << endl;

    return buffer_str;
}

/*
   Performs a full hybrid key exchange (PQC + ECDH + optional QKD)
   and derives a new session key.
*/
std::vector<unsigned char> rekey_cli(tcp::socket &client_socket, string qkd_ip, const char *srv_ip, string buffer_str, const std::string &chosen_pqc_alg)
{
    std::vector<unsigned char> sec_key(AES_GCM_KEY_LEN * 2);

    std::string salt_str = receive_framed_message(client_socket);
    std::vector<uint8_t> salt_bytes(salt_str.begin(), salt_str.end());
    std::cout << "Client: received salt (len=" << salt_bytes.size() << ")\n";
    std::cout << "DEBUG: salt(hex) = " << to_hex(salt_bytes) << std::endl;

    PQCKeyMaterial pqc_material;
    if (chosen_pqc_alg == "hqc-256")
    {
        std::cout << "Client: Using HQC-256 for PQC key exchange.\n";
        pqc_material = get_pqckey_hqc(client_socket);
    }
    else
    {
        std::cout << "Client: Using ML-KEM-768 for PQC key exchange.\n";
        pqc_material = get_pqckey(client_socket, chosen_pqc_alg);
    }
    
    if (pqc_material.shared_secret.empty())
    {
        std::cerr << "Client: PQC key derivation failed.\n";
        return {};
    }
    std::cout << "PQC key established.\n";
    std::cout << "DEBUG: PQC shared secret(hex) = " << to_hex_snippet(pqc_material.shared_secret) << std::endl;
    std::cout << "DEBUG: PQC ciphertext(hex) = " << to_hex_snippet(pqc_material.ciphertext) << std::endl;

    ECDHKeyMaterial ecdh_material = PerformECDHKeyExchange(client_socket);
    if (ecdh_material.shared_secret.empty())
    {
        std::cerr << "Client: ECDH key derivation failed.\n";
        return {};
    }
    std::cout << "ECDH key established.\n";
    std::cout << "DEBUG: ECDH shared secret(hex) = " << to_hex_snippet(ecdh_material.shared_secret) << std::endl;

    if (qkd_ip.empty())
    {
        auto k1 = hmac_sha512(salt_bytes, pqc_material.shared_secret);
        auto k2 = hmac_sha512(salt_bytes, ecdh_material.shared_secret);

        std::vector<uint8_t> p1_input = pqc_material.ciphertext;
        p1_input.insert(p1_input.end(), pqc_material.shared_secret.begin(), pqc_material.shared_secret.end());
        auto p1 = sha3_512(p1_input);

        std::vector<uint8_t> p2_input;
        if (ecdh_material.own_pubkey < ecdh_material.peer_pubkey)
        {
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
        }
        else
        {
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
        }
        p2_input.insert(p2_input.end(), ecdh_material.shared_secret.begin(), ecdh_material.shared_secret.end());
        auto p2 = sha3_512(p2_input);

        auto s1 = hmac_sha512(p1, k1);
        auto s2 = hmac_sha512(p2, k2);

        auto hybrid_key = xorVectors(s1, s2);
        std::cout << "DEBUG: hybrid_key(hex) = " << to_hex_snippet(hybrid_key) << std::endl;

        auto final_digest = sha3_512(hybrid_key);
        std::cout << "DEBUG: final_digest(hex) = " << to_hex(final_digest) << std::endl;

        if (sec_key.size() > final_digest.size())
        {
            throw std::runtime_error("Session key buffer is larger than the derived digest.");
        }
        std::copy_n(final_digest.begin(), sec_key.size(), sec_key.begin());

        OPENSSL_cleanse(k1.data(), k1.size());
        OPENSSL_cleanse(k2.data(), k2.size());
        OPENSSL_cleanse(p1.data(), p1.size());
        OPENSSL_cleanse(p2.data(), p2.size());
        OPENSSL_cleanse(s1.data(), s1.size());
        OPENSSL_cleanse(s2.data(), s2.size());
        OPENSSL_cleanse(hybrid_key.data(), hybrid_key.size());
        OPENSSL_cleanse(final_digest.data(), final_digest.size());
        OPENSSL_cleanse(pqc_material.shared_secret.data(), pqc_material.shared_secret.size());
        OPENSSL_cleanse(ecdh_material.shared_secret.data(), ecdh_material.shared_secret.size());

        std::cout << "Session key: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
    else
    {
        buffer_str = get_qkdkey(qkd_ip, client_socket);
        std::vector<uint8_t> qkd_key_bytes(buffer_str.begin(), buffer_str.end());
        std::vector<uint8_t> qkd_param_bytes(qkd_parameter.begin(), qkd_parameter.end());

        auto k1 = hmac_sha512(salt_bytes, pqc_material.shared_secret);
        auto k2 = hmac_sha512(salt_bytes, ecdh_material.shared_secret);
        auto k3 = hmac_sha512(salt_bytes, qkd_key_bytes);

        std::vector<uint8_t> p1_input = pqc_material.ciphertext;
        p1_input.insert(p1_input.end(), pqc_material.shared_secret.begin(), pqc_material.shared_secret.end());
        auto p1 = sha3_512(p1_input);

        std::vector<uint8_t> p2_input;
        if (ecdh_material.own_pubkey < ecdh_material.peer_pubkey)
        {
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
        }
        else
        {
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
        }
        p2_input.insert(p2_input.end(), ecdh_material.shared_secret.begin(), ecdh_material.shared_secret.end());
        auto p2 = sha3_512(p2_input);

        std::vector<uint8_t> p3_input = qkd_param_bytes;
        p3_input.insert(p3_input.end(), qkd_key_bytes.begin(), qkd_key_bytes.end());
        auto p3 = sha3_512(p3_input);

        auto s1 = hmac_sha512(p1, k1);
        auto s2 = hmac_sha512(p2, k2);
        auto s3 = hmac_sha512(p3, k3);

        auto hybrid_key = xorVectors(xorVectors(s1, s2), s3);
        auto final_digest = sha3_512(hybrid_key);

        if (sec_key.size() > final_digest.size())
        {
            throw std::runtime_error("Session key buffer is larger than the derived digest.");
        }
        std::copy_n(final_digest.begin(), sec_key.size(), sec_key.begin());

        OPENSSL_cleanse(k1.data(), k1.size());
        OPENSSL_cleanse(k2.data(), k2.size());
        OPENSSL_cleanse(k3.data(), k3.size());
        OPENSSL_cleanse(p1.data(), p1.size());
        OPENSSL_cleanse(p2.data(), p2.size());
        OPENSSL_cleanse(p3.data(), p3.size());
        OPENSSL_cleanse(s1.data(), s1.size());
        OPENSSL_cleanse(s2.data(), s2.size());
        OPENSSL_cleanse(s3.data(), s3.size());
        OPENSSL_cleanse(hybrid_key.data(), hybrid_key.size());
        OPENSSL_cleanse(final_digest.data(), final_digest.size());
        OPENSSL_cleanse(pqc_material.shared_secret.data(), pqc_material.shared_secret.size());
        OPENSSL_cleanse(ecdh_material.shared_secret.data(), ecdh_material.shared_secret.size());
        OPENSSL_cleanse(qkd_key_bytes.data(), qkd_key_bytes.size());

        std::cout << "Session key: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
}

int main(int argc, char *argv[])
{
    if (argc < 1 || argc > 3)
    {
        help();
        return 1;
    }
    const char *srv_ip = argv[1];
    std::string qkd_ip;
    if (argc == 3)
    {
        qkd_ip = argv[2];
    }
    int choice;
    std::string chosen_pqc_alg;
    std::cout << "Choose PQC Algorithm:\n1. MLKEM768 (Kyber768)\n2. HQC-256\nEnter choice: ";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        chosen_pqc_alg = "ML-KEM-768";
        break;
    case 2:
        chosen_pqc_alg = "hqc-256";
        break;
    default:
        std::cerr << "Invalid choice, defaulting to Kyber768\n";
        chosen_pqc_alg = "ML-KEM-768";
        break;
    }
    std::cout << "Selected PQC Algorithm: " << chosen_pqc_alg << std::endl;

    
    int tundesc = -1;
    try
    {
        tundesc = tun_open();
        std::cout << "TUN device tun0 opened successfully.\n";
    }
    catch (const std::exception &e)
    {
        std::cerr << "Fatal error creating TUN device: " << e.what() << std::endl;
        return 1;
    }


    EVP_CIPHER_CTX *enc_ctx = EVP_CIPHER_CTX_new();
    EVP_CIPHER_CTX *dec_ctx = EVP_CIPHER_CTX_new();
    if (!enc_ctx || !dec_ctx)
    {
        std::cerr << "Failed to allocate cipher contexts\n";
        EVP_CIPHER_CTX_free(enc_ctx);
        EVP_CIPHER_CTX_free(dec_ctx);
        close(tundesc);
        return 1;
    }

    std::atomic<bool> app_shutdown_flag{false};
    std::atomic<bool> client_rekey_flag{false};

    std::thread rekey_thread([&client_rekey_flag, &app_shutdown_flag]()
                             {
        while (!app_shutdown_flag) { 
            std::this_thread::sleep_for(std::chrono::hours(1));
            client_rekey_flag.store(true);
        } });

    while (true)
    {
        try
        {
            boost::asio::io_context io_context;
            tcp::socket tcp_socket(io_context);
            tcp::resolver resolver(io_context);
            boost::asio::connect(tcp_socket, resolver.resolve(srv_ip, std::to_string(KEYPORT)));
            std::cout << "Connected to server\n";

            // Disable Nagle's algorithm for responsive key exchange over TCP
            tcp_socket.set_option(tcp::no_delay(true));

            char ready_buf[5] = {0};
            boost::asio::read(tcp_socket, boost::asio::buffer(ready_buf, 5));
            std::cout << "Server READY received\n";

            const std::string init_rekey_msg = "INIT_REKEY";
            boost::asio::write(tcp_socket, boost::asio::buffer(init_rekey_msg));

            std::vector<uint8_t> sec_key;
            sec_key = rekey_cli(tcp_socket, qkd_ip, srv_ip, "", chosen_pqc_alg);

            std::vector<unsigned char> key_encrypt(sec_key.begin(), sec_key.begin() + AES_GCM_KEY_LEN);
            std::vector<unsigned char> key_decrypt(sec_key.begin() + AES_GCM_KEY_LEN, sec_key.end());
            std::cout << "Initial rekey done, keys established\n";

            // Receive the dedicated UDP port from the server
            std::string udp_port_str = receive_framed_message(tcp_socket);
            unsigned short server_udp_port = std::stoi(udp_port_str);
            std::cout << "Server assigned dedicated UDP port: " << server_udp_port << std::endl;

            udp::socket udp_socket(io_context);
            udp::resolver udp_resolver(io_context);
            udp::endpoint server_udp_ep = *udp_resolver.resolve(udp::v4(), srv_ip, std::to_string(server_udp_port)).begin();
            udp_socket.open(udp::v4());

            boost::system::error_code ec;
            udp_socket.send_to(boost::asio::buffer("Hello from client UDP"), server_udp_ep, 0, ec);
            std::cout << "Client UDP hello sent\n";

            char udp_reply[1024] = {0};
            udp::endpoint server_reply_ep;
            udp_socket.receive_from(boost::asio::buffer(udp_reply), server_reply_ep);
            std::cout << "Received UDP reply from server: " << std::string(udp_reply) << "\n";

            const std::chrono::seconds keepalive_interval(15);
            auto last_udp_send_time = std::chrono::steady_clock::now();
            const std::string keepalive_msg_to_server = "KEEPALIVE_C";
            udp_socket.non_blocking(true);
            tcp_socket.non_blocking(true);

            constexpr size_t IO_BUF_SIZE = AES_GCM_IV_LEN + MAXLINE + TAG_SIZE;

            udp_socket.set_option(boost::asio::socket_base::receive_buffer_size(4 * 1024 * 1024), ec);
            udp_socket.set_option(boost::asio::socket_base::send_buffer_size(4 * 1024 * 1024), ec);

            std::shared_mutex keys_mutex;
            std::atomic<bool> io_running{true};

            int tcp_fd = tcp_socket.native_handle();
            int udp_fd = udp_socket.native_handle();

            // Thread 1 — TUN → encrypt → UDP; also owns the keepalive sender
            std::thread enc_thread([&]() {
                std::vector<uint8_t> enc_buf(IO_BUF_SIZE);
                int efd = epoll_create1(EPOLL_CLOEXEC);
                struct epoll_event ev{};
                ev.events = EPOLLIN;
                ev.data.fd = tundesc;
                epoll_ctl(efd, EPOLL_CTL_ADD, tundesc, &ev);
                struct epoll_event evs[2];
                auto last_send = std::chrono::steady_clock::now();

                while (io_running.load(std::memory_order_relaxed))
                {
                    int n = epoll_wait(efd, evs, 2, 100);
                    if (n > 0)
                    {
                        std::shared_lock lock(keys_mutex);
                        bool sent = false;
                        while (E_N_C_R(enc_ctx, udp_socket, server_udp_ep, key_encrypt, tundesc, enc_buf.data()))
                            sent = true;
                        if (sent)
                            last_send = std::chrono::steady_clock::now();
                    }
                    else if (n == 0)
                    {
                        auto now = std::chrono::steady_clock::now();
                        if (now - last_send > keepalive_interval)
                        {
                            boost::system::error_code ka_ec;
                            udp_socket.send_to(boost::asio::buffer(keepalive_msg_to_server), server_udp_ep, 0, ka_ec);
                            last_send = now;
                        }
                    }
                }
                close(efd);
            });

            // Thread 2 — UDP → decrypt → TUN
            std::thread dec_thread([&]() {
                std::vector<uint8_t> dec_buf(IO_BUF_SIZE);
                udp::endpoint recv_ep;
                int efd = epoll_create1(EPOLL_CLOEXEC);
                struct epoll_event ev{};
                ev.events = EPOLLIN;
                ev.data.fd = udp_fd;
                epoll_ctl(efd, EPOLL_CTL_ADD, udp_fd, &ev);
                struct epoll_event evs[2];

                while (io_running.load(std::memory_order_relaxed))
                {
                    if (epoll_wait(efd, evs, 2, 100) > 0)
                    {
                        std::shared_lock lock(keys_mutex);
                        while (D_E_C_R(dec_ctx, udp_socket, recv_ep, key_decrypt, tundesc, dec_buf.data())) {}
                    }
                }
                close(efd);
            });

            // Main thread — TCP: client-initiated and server-initiated rekey
            int tcp_efd = epoll_create1(EPOLL_CLOEXEC);
            {
                struct epoll_event ev{};
                ev.events = EPOLLIN;
                ev.data.fd = tcp_fd;
                epoll_ctl(tcp_efd, EPOLL_CTL_ADD, tcp_fd, &ev);
            }
            struct epoll_event events[2];
            bool connection_shutdown_flag = false;
            char tcp_buf[1024];

            while (!connection_shutdown_flag)
            {
                // Check 1-hour rekey timer before blocking in epoll
                if (client_rekey_flag.load())
                {
                    std::cout << "Periodic rekey triggered by client timer.\n";
                    tcp_socket.non_blocking(false, ec);
                    boost::asio::write(tcp_socket, boost::asio::buffer("REKEY_CLIENT_INITIATED"));
                    client_rekey_flag.store(false);
                    {
                        std::unique_lock lock(keys_mutex);
                        std::string qkd_key_buffer;
                        if (!qkd_ip.empty())
                            qkd_key_buffer = get_qkdkey(qkd_ip, tcp_socket);
                        sec_key = rekey_cli(tcp_socket, qkd_ip, srv_ip, qkd_key_buffer, chosen_pqc_alg);
                        if (!sec_key.empty())
                        {
                            key_encrypt.assign(sec_key.begin(), sec_key.begin() + AES_GCM_KEY_LEN);
                            key_decrypt.assign(sec_key.begin() + AES_GCM_KEY_LEN, sec_key.end());
                            std::cout << "Client-initiated rekey completed\n";
                        }
                        else
                        {
                            std::cerr << "Client-initiated rekey failed, closing connection.\n";
                            connection_shutdown_flag = true;
                        }
                    }
                    tcp_socket.non_blocking(true, ec);
                    continue;
                }

                if (epoll_wait(tcp_efd, events, 2, 100) <= 0)
                    continue;

                size_t len = tcp_socket.read_some(boost::asio::buffer(tcp_buf), ec);
                if (!ec && len > 0)
                {
                    if (std::string(tcp_buf, len) == "REKEY_SERVER_INITIATED")
                    {
                        tcp_socket.non_blocking(false, ec);
                        {
                            std::unique_lock lock(keys_mutex);
                            std::string qkd_key_buffer;
                            if (!qkd_ip.empty())
                                qkd_key_buffer = get_qkdkey(qkd_ip, tcp_socket);
                            sec_key = rekey_cli(tcp_socket, qkd_ip, srv_ip, qkd_key_buffer, chosen_pqc_alg);
                            if (!sec_key.empty())
                            {
                                key_encrypt.assign(sec_key.begin(), sec_key.begin() + AES_GCM_KEY_LEN);
                                key_decrypt.assign(sec_key.begin() + AES_GCM_KEY_LEN, sec_key.end());
                                std::cout << "Server-initiated rekey completed\n";
                            }
                            else
                            {
                                std::cerr << "Server-initiated rekey failed, closing connection.\n";
                                connection_shutdown_flag = true;
                            }
                        }
                        tcp_socket.non_blocking(true, ec);
                    }
                }
                else if (ec != boost::asio::error::would_block)
                {
                    std::cerr << "TCP connection error or closed: " << ec.message() << "\n";
                    connection_shutdown_flag = true;
                }
            }

            io_running.store(false);
            enc_thread.join();
            dec_thread.join();
            close(tcp_efd);

            std::cout << "Connection closing. Cleaning up resources.\n";
            tcp_socket.close();
            udp_socket.close();
        }
        catch (const std::exception &e)
        {
            std::cerr << "Client exception: " << e.what() << "\nRetrying in 5s...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    if (tundesc != -1)
    {
        close(tundesc);
    }

    EVP_CIPHER_CTX_free(enc_ctx);
    EVP_CIPHER_CTX_free(dec_ctx);

    app_shutdown_flag.store(true);
    if (rekey_thread.joinable())
    {
        rekey_thread.join();
    }
    return 0;
}