#include <thread>
#include <atomic>
#include <ctime>
#include <utility>        // For std::exchange, must be before asio
#include <boost/asio.hpp> // Include Boost.Asio before system network headers
#include <fstream>
#include <sstream>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <linux/if.h> // Now included after Boost.Asio
#include <linux/if_tun.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string>
#include <cstring>
#include <cstdlib>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <iomanip>
#include <cstdint>
#include <stdexcept>
#include <algorithm>
#include <openssl/evp.h>
#include <openssl/core_names.h>
#include <openssl/provider.h>
#include <vector>
#include <map> // Added for PQC algorithm properties
#include <list>
#include <openssl/rand.h>
#include <openssl/hmac.h>
#include <openssl/objects.h>
#include <string_view> // Added for string_view

using boost::asio::ip::tcp;
using boost::asio::ip::udp;

#define PORT 62000
#define KEYPORT 61000
#define MAXLINE 4096
#define AES_GCM_KEY_LEN 32
#define AES_GCM_IV_LEN 12
#define TAG_SIZE 16

#define VALIDATE_CERT "client.crt" // Název souboru serverového certifikátu
#define CLIENT_CA_CERT "ca.crt"    // Cesta k certifikátu certifikační autority klienta

#include <iostream>
using std::cerr;
using std::cout;
using std::endl;

#include <string>
using std::string;

#include "assert.h"
#include <mutex>

std::string to_hex_snippet(const std::vector<uint8_t> &data, size_t len = 32);

std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t> &key, const std::vector<uint8_t> &data);
std::vector<uint8_t> sha3_512(const std::vector<uint8_t> &data);

string xy_str;
string kyber_cipher_data_str;
string qkd_parameter;
std::mutex m1;

int get_order(std::atomic<int> &read_order)
{
    m1.lock();
    read_order = (read_order % 100000) + 1;
    int order = read_order;
    m1.unlock();
    return order;
}

void send_framed_message(tcp::socket &socket, const std::string &msg)
{
    uint32_t msg_len = htonl(msg.length());
    boost::asio::write(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)));
    boost::asio::write(socket, boost::asio::buffer(msg));
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

void cert_authenticate_online()
{
    int counter = 0;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *acc, *client;

    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        printf("Error while creating context\n");
        exit(EXIT_FAILURE);
    }

    if (SSL_CTX_load_verify_locations(ctx, CLIENT_CA_CERT, NULL) != 1)
    {
        printf("Error loading a client CA certificate.\n");
        exit(EXIT_FAILURE);
    }

    acc = BIO_new_accept("61000");
    if (acc == NULL)
    {
        printf("Error creating BIO acceptor.\n");
        exit(EXIT_FAILURE);
    }

    if (BIO_do_accept(acc) <= 0)
    {
        printf("Error adding acceptor to context.\n");
        exit(EXIT_FAILURE);
    }

    while (counter < 1)
    {
        if (BIO_do_accept(acc) <= 0)
        {
            printf("Error while receiving.\n");
            exit(EXIT_FAILURE);
        }

        client = BIO_pop(acc);
        if (client == NULL)
        {
            printf("Error acquiring client BIO.\n");
            exit(EXIT_FAILURE);
        }

        ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            printf("Error while creating SSL connection.\n");
            exit(EXIT_FAILURE);
        }

        SSL_set_bio(ssl, client, client);

        if (SSL_accept(ssl) <= 0)
        {
            printf("Error when establishing SSL connection.\n");
            exit(EXIT_FAILURE);
        }

        if (SSL_get_verify_result(ssl) != X509_V_OK)
        {
            printf("Error while verifying the certificate.\n");
            exit(EXIT_FAILURE);
        }

        SSL_shutdown(ssl);
        SSL_free(ssl);
        counter++;
    }

    BIO_free(acc);
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

    file = fopen(CLIENT_CA_CERT, "r");
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

    X509_STORE_CTX_free(ctx);
    X509_STORE_free(store);
    X509_free(serverCert);
    X509_free(caCert);
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
    char buffer[MAXLINE] = {0};
    boost::system::error_code error;
    size_t n = socket.receive_from(boost::asio::buffer(buffer), remote_endpoint, 0, error);

    if (error && error != boost::asio::error::message_size)
    {
        return "";
    }

    string recieved(buffer, n);

    return recieved;
}

const std::string keepalive_msg_from_client = "KEEPALIVE_C";

bool is_keepalive_from_client(const std::string &msg)
{
    return msg == keepalive_msg_from_client;
}

string read_tun(int tundesc)
{

    char buf[MAXLINE - 60] = {0};
    int nbytes = read(tundesc, buf, sizeof(buf));
    if (nbytes == -1)
    {
        return "";
    }
    string data(buf, nbytes);

    return data;
}

/* Virtual interface data write.
   Data will appear as if it arrived at
   virtual interface and can be routed further */

void write_tun(int tundesc, string message)
{
    write(tundesc, message.data(), message.length());
}

void send_encrypted(udp::socket &socket, udp::endpoint &remote_endpoint, const string &cipher)
{
    socket.send_to(boost::asio::buffer(cipher), remote_endpoint);
}

string encrypt_data(const std::vector<unsigned char> &key, const string &plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    std::vector<unsigned char> iv(AES_GCM_IV_LEN);
    std::vector<unsigned char> ciphertext(plaintext.length());
    std::vector<unsigned char> tag(TAG_SIZE);

    if (1 != RAND_bytes(iv.data(), iv.size()))
    {
        std::cerr << "Error: Failed to generate IV." << std::endl;
        return "";
    }

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return "";
    if (1 != EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return "";
    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, iv.size(), NULL))
        return "";
    if (1 != EVP_EncryptInit_ex(ctx, NULL, NULL, key.data(), iv.data()))
        return "";

    if (1 != EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (const unsigned char *)plaintext.c_str(), plaintext.length()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len = len;

    if (1 != EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len))
    {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }
    ciphertext_len += len;
    ciphertext.resize(ciphertext_len);

    if (1 != EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_SIZE, tag.data()))
    {
        EVP_CIPHER_CTX_free(ctx);
        return "";
    }

    EVP_CIPHER_CTX_free(ctx);

    // Prepend IV and append tag to ciphertext
    string result(reinterpret_cast<const char *>(iv.data()), iv.size());
    result.append(reinterpret_cast<const char *>(ciphertext.data()), ciphertext.size());
    result.append(reinterpret_cast<const char *>(tag.data()), tag.size());

    return result;
}

string decrypt_data(const std::vector<unsigned char> &key, const string &cipher_with_iv_tag)
{
    if (cipher_with_iv_tag.length() < AES_GCM_IV_LEN + TAG_SIZE)
    {
        return ""; // Not enough data
    }

    EVP_CIPHER_CTX *ctx;
    int len;
    int plaintext_len;

    const unsigned char *iv = (const unsigned char *)cipher_with_iv_tag.data();
    const unsigned char *ciphertext = iv + AES_GCM_IV_LEN;
    size_t ciphertext_len_val = cipher_with_iv_tag.length() - AES_GCM_IV_LEN - TAG_SIZE;
    const unsigned char *tag = ciphertext + ciphertext_len_val;
    std::vector<unsigned char> plaintext(ciphertext_len_val);

    if (!(ctx = EVP_CIPHER_CTX_new()))
        return "";
    if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL))
        return "";
    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, AES_GCM_IV_LEN, NULL))
        return "";
    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key.data(), iv))
        return "";
    if (!EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext, ciphertext_len_val))
        return "";
    plaintext_len = len;

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_SIZE, (void *)tag))
        return "";

    int ret = EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    EVP_CIPHER_CTX_free(ctx);

    if (ret > 0)
    {
        plaintext_len += len;
        plaintext.resize(plaintext_len);
        return string(reinterpret_cast<const char *>(plaintext.data()), plaintext.size());
    }
    else
    {
        return ""; // Authentication failed
    }
}

/*
   Receives, decrypts, and writes data to the TUN interface.
   Returns false if there are no more data available on socket.
*/
bool D_E_C_R(udp::socket &socket, udp::endpoint &remote_endpoint, const std::vector<unsigned char> &key, int tundesc, std::atomic<int> &read_order, std::atomic<int> &send_order)
{
    string data;
    string encrypted_data = data_recieve(socket, remote_endpoint);
    if (is_keepalive_from_client(encrypted_data))
    {
        // It's just a keep-alive from the client, ignore it and report no real data.
        return false;
    }

    if (encrypted_data.length() < AES_GCM_IV_LEN + TAG_SIZE + 1)
    {
        return false;
    }

    int order = get_order(read_order);

    try
    {
        data = decrypt_data(key, encrypted_data);
    }
    catch (...)
    {
        while (order != send_order)
        {
        }
        send_order = (send_order % 100000) + 1;
        return true;
    }
    while (order != send_order)
    {
    }

    write_tun(tundesc, data);
    send_order = (send_order % 100000) + 1;
    return true;
}

/*
   Reads from the TUN interface, encrypts, and sends data.
   Returns false if there are no more data available on virtual interface.
*/
bool E_N_C_R(udp::socket &socket, udp::endpoint &remote_endpoint, const std::vector<unsigned char> &key, int tundesc, std::atomic<int> &read_order, std::atomic<int> &send_order)
{
    string data = read_tun(tundesc);

    if (data.length() == 0)
    {
        return false;
    }

    int order = get_order(read_order);
    string encrypted_data = encrypt_data(key, data);

    while (order != send_order)
    {
    }

    send_encrypted(socket, remote_endpoint, encrypted_data);
    send_order = (send_order % 100000) + 1;
    return true;
}

void thread_encrypt(udp::socket *socket, udp::endpoint remote_endpoint, const std::vector<unsigned char> *key_encrypt, const std::vector<unsigned char> *key_decrypt, int tundesc, std::atomic<int> *threads, std::atomic<int> *read_order, std::atomic<int> *send_order)
{
    for (int i = 0; i < 100; i++)
    {
        while (E_N_C_R(*socket, remote_endpoint, *key_encrypt, tundesc, *read_order, *send_order))
        {
        }
        while (D_E_C_R(*socket, remote_endpoint, *key_decrypt, tundesc, *read_order, *send_order))
        {
        }
    }
    *threads += 1;
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

EVP_PKEY *generate_pqc_keypair(const std::string &alg_name,
                               std::vector<unsigned char> &raw_pubkey)
{
    const char *alg = alg_name.c_str();

    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    if (!pkey)
    {
        std::cerr << "generate_pqc_keypair: EVP_PKEY_Q_keygen failed for " << alg << "\n";
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    size_t pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(
            pkey,
            OSSL_PKEY_PARAM_PUB_KEY,
            NULL, 0, &pub_len) != 1 ||
        pub_len == 0)
    {
        std::cerr << "generate_pqc_keypair: failed to query public key length for " << alg << "\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    raw_pubkey.resize(pub_len);
    if (EVP_PKEY_get_octet_string_param(
            pkey,
            OSSL_PKEY_PARAM_PUB_KEY,
            raw_pubkey.data(), raw_pubkey.size(), &pub_len) != 1)
    {
        std::cerr << "generate_pqc_keypair: failed to export public key for " << alg << "\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(pkey);
        return nullptr;
    }

    return pkey;
}
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

bool decapsulate_kyber768(EVP_PKEY *private_key,
                          const std::vector<uint8_t> &ciphertext,
                          std::vector<uint8_t> &shared_secret)
{
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_from_pkey(NULL, private_key, NULL);
    if (!ctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_pkey failed." << std::endl;
        ERR_print_errors_fp(stderr);
        return false;
    }

    if (EVP_PKEY_decapsulate_init(ctx, NULL) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_decapsulate_init failed." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    size_t secret_len = 0;
    if (EVP_PKEY_decapsulate(ctx, NULL, &secret_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_decapsulate (for length) failed." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    shared_secret.resize(secret_len);
    if (EVP_PKEY_decapsulate(ctx, shared_secret.data(), &secret_len, ciphertext.data(), ciphertext.size()) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_decapsulate failed." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY_CTX_free(ctx);
    return true;
}

struct PQCKeyMaterial
{
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> ciphertext;
};

struct ECDHKeyMaterial
{
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> peer_pubkey;
    std::vector<uint8_t> own_pubkey;
};

PQCKeyMaterial get_pqckey(tcp::socket &new_socket, const std::string &alg_name)
{
    PQC_Alg_Properties props = get_pqc_alg_properties(alg_name);

    EVP_PKEY *server_private_key = nullptr;
    std::vector<uint8_t> _shrd_key(props.shared_secret_len, 0);
    std::vector<unsigned char> raw_pubkey;

    server_private_key = generate_pqc_keypair(alg_name, raw_pubkey);
    if (!server_private_key)
    {
        std::cerr << "Error: Failed to generate server keypair.\n";
        return {};
    }

    if (raw_pubkey.size() != props.pubkey_len)
    {
        std::cerr << "Warning: raw_pubkey.size()=" << raw_pubkey.size()
                  << " != props.pubkey_len=" << props.pubkey_len << "\n";
    }
    std::cout << "Server DEBUG: pubkey(hex) = " << to_hex(raw_pubkey) << "\n";

    try
    {
        send_framed_message(new_socket, std::string(raw_pubkey.begin(), raw_pubkey.end()));
        std::cout << "Server: sent PQC public key.\n";
    }
    catch (...)
    {
        std::cerr << "Error: Failed to send public key.\n";
        EVP_PKEY_free(server_private_key);
        return {};
    }

    std::string cipher_str = receive_framed_message(new_socket);
    std::vector<uint8_t> cipher_buf(cipher_str.begin(), cipher_str.end());

    std::cout << "Server DEBUG: received ciphertext len = " << cipher_buf.size() << "\n";
    std::cout << "Server DEBUG: received ciphertext(hex) = " << to_hex(cipher_buf) << "\n";

    if (!decapsulate_kyber768(server_private_key, cipher_buf, _shrd_key))
    {
        std::cerr << "Error: Kyber decapsulation failed.\n";
        EVP_PKEY_free(server_private_key);
        return {}; // Return empty struct on failure
    }
    std::cout << "Server DEBUG: PQC shared secret(hex) = " << to_hex_snippet(_shrd_key) << "\n";

    EVP_PKEY_free(server_private_key);
    return {_shrd_key, cipher_buf};
}

string get_qkdkey(string qkd_ip, tcp::socket &new_socket)
{
    // This function still uses std::string because the external `sym-ExpQKD` tool
    // and file I/O seem to be text-based. The output is converted to binary inside the KDF.
    char buffer[MAXLINE] = {0};
    boost::system::error_code ec;
    size_t len = new_socket.read_some(boost::asio::buffer(buffer), ec);
    if (ec || len == 0)
    {
        return "";
    }
    std::string bufferTCP(buffer, len);

    std::ofstream myfile;
    myfile.open("keyID");
    myfile << bufferTCP;
    myfile.close();

    system(("./sym-ExpQKD 'server' " + qkd_ip).c_str());

    cout << "QKD keyID recieved: " << bufferTCP << endl;

    // Hash content of bufferTCP with SHAKE128 using OpenSSL
    std::vector<unsigned char> shake_output(216);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    const EVP_MD *shake128 = EVP_shake128();
    EVP_DigestInit_ex(mdctx, shake128, NULL);
    EVP_DigestUpdate(mdctx, bufferTCP.c_str(), bufferTCP.length());
    EVP_DigestFinalXOF(mdctx, shake_output.data(), shake_output.size());
    EVP_MD_CTX_free(mdctx);

    string pom_param = to_hex(shake_output);

    qkd_parameter = pom_param + bufferTCP.substr(0, 216);

    std::ifstream key_file("key");
    std::stringstream key_buffer;
    key_buffer << key_file.rdbuf();
    cout << "QKD key established:" << key_buffer.str() << endl;
    return key_buffer.str();
}

void help()
{
    cout << endl
         << "   Usage:" << endl
         << endl;
    cout << "   ./encryptor_server [QKD IP]" << endl;
    cout << "   QKD IP - Local QKD system IP address {x.x.x.x} (optional)" << endl
         << endl;
}

ECDHKeyMaterial PerformECDHKeyExchange(tcp::socket &sock)
{
    EVP_PKEY *server_key = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY *peer_key = nullptr;
    unsigned char *shared_secret = nullptr;
    size_t shared_secret_len = 0;
    std::vector<uint8_t> final_shared_secret_bytes;

    pctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!pctx ||
        EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_ec_paramgen_curve_nid(pctx, NID_secp521r1) <= 0 ||
        EVP_PKEY_keygen(pctx, &server_key) <= 0)
    {
        std::cerr << "Error: Failed to generate server ECDH key." << std::endl;
        ERR_print_errors_fp(stderr);
        if (pctx)
            EVP_PKEY_CTX_free(pctx);
        return {};
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = nullptr;

    size_t server_pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(server_key,
                                        OSSL_PKEY_PARAM_PUB_KEY,
                                        NULL, 0, &server_pub_len) <= 0)
    {
        std::cerr << "Error: Failed to get server EC public key length." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(server_key);
        return {};
    }

    std::vector<unsigned char> server_pub(server_pub_len);
    if (EVP_PKEY_get_octet_string_param(server_key,
                                        OSSL_PKEY_PARAM_PUB_KEY,
                                        server_pub.data(), server_pub.size(),
                                        &server_pub_len) <= 0)
    {
        std::cerr << "Error: Failed to get server EC public key bytes." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(server_key);
        return {};
    }

    std::string client_pub_str;
    try
    {
        client_pub_str = receive_framed_message(sock);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to read client's ECDH public key (framed): "
                  << e.what() << std::endl;
        EVP_PKEY_free(server_key);
        return {};
    }

    std::vector<unsigned char> client_pub(client_pub_str.begin(), client_pub_str.end());

    std::cout << "Server DEBUG: received client_pub len=" << client_pub.size() << std::endl;
    if (!client_pub.empty())
    {
        std::cout << "Server DEBUG: client_pub[0]=0x"
                  << std::hex << std::uppercase << (int)client_pub[0]
                  << " (expect 0x04 for uncompressed)" << std::dec << std::endl;
    }

    if (client_pub.size() != 133)
    {
        std::cerr << "Warning: client_pub size is " << client_pub.size()
                  << " (expected 133 for P-521 uncompressed)." << std::endl;
    }

    try
    {
        send_framed_message(sock, std::string(server_pub.begin(), server_pub.end()));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to send server ECDH public key (framed): "
                  << e.what() << std::endl;
        EVP_PKEY_free(server_key);
        return {};
    }

    EVP_PKEY_CTX *fromctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!fromctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_name(NULL, \"EC\", NULL) failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(server_key);
        return {};
    }
    if (EVP_PKEY_fromdata_init(fromctx) != 1)
    {
        std::cerr << "Error: EVP_PKEY_fromdata_init failed" << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(fromctx);
        EVP_PKEY_free(server_key);
        return {};
    }

    OSSL_PARAM params[3];
    params[0] = OSSL_PARAM_construct_utf8_string(
        "group",
        const_cast<char *>("secp521r1"),
        0);
    params[1] = OSSL_PARAM_construct_octet_string(
        OSSL_PKEY_PARAM_PUB_KEY,
        const_cast<unsigned char *>(client_pub.data()),
        client_pub.size());
    params[2] = OSSL_PARAM_construct_end();

    if (EVP_PKEY_fromdata(fromctx, &peer_key, EVP_PKEY_PUBLIC_KEY, params) != 1)
    {
        std::cerr << "Error: EVP_PKEY_fromdata failed to create EC public key from client bytes"
                  << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(fromctx);
        EVP_PKEY_free(server_key);
        return {};
    }

    EVP_PKEY_CTX_free(fromctx);
    fromctx = nullptr;

    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, server_key, NULL);
    if (!dctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_pkey for derive failed." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(server_key);
        return {};
    }

    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0 ||
        EVP_PKEY_derive(dctx, NULL, &shared_secret_len) <= 0)
    {
        std::cerr << "Error: Failed to determine shared secret length." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(server_key);
        return {};
    }

    shared_secret = (unsigned char *)OPENSSL_malloc(shared_secret_len);
    if (!shared_secret)
    {
        std::cerr << "Error: OPENSSL_malloc for shared_secret failed." << std::endl;
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(server_key);
        return {};
    }

    if (EVP_PKEY_derive(dctx, shared_secret, &shared_secret_len) <= 0)
    {
        std::cerr << "Error: Failed to derive shared secret." << std::endl;
        ERR_print_errors_fp(stderr);
        OPENSSL_free(shared_secret);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(server_key);
        return {};
    }

    final_shared_secret_bytes.assign(shared_secret, shared_secret + shared_secret_len);

    OPENSSL_free(shared_secret);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(server_key);

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

    return to_hex(result_bytes);
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

/*
   Performs a full hybrid key exchange (PQC + ECDH + optional QKD)
   and derives a new session key.
*/
std::vector<unsigned char> rekey_srv(tcp::socket &new_socket, std::string qkd_ip, const std::string &chosen_pqc_alg)
{
    std::vector<unsigned char> sec_key(AES_GCM_KEY_LEN * 2);

    std::vector<uint8_t> salt_bytes(64);
    if (RAND_bytes(salt_bytes.data(), salt_bytes.size()) != 1)
    {
        std::cerr << "Error: Failed to generate salt for HMAC.\n";
        return {};
    }
    send_framed_message(new_socket, std::string(salt_bytes.begin(), salt_bytes.end()));
    std::cout << "Server: sent salt (len=" << salt_bytes.size() << ")\n";
    std::cout << "DEBUG: salt(hex) = " << to_hex(salt_bytes) << std::endl;

    PQCKeyMaterial pqc_material = get_pqckey(new_socket, chosen_pqc_alg);
    if (pqc_material.shared_secret.empty())
    {
        std::cerr << "Server: PQC key derivation failed.\n";
        return {};
    }
    std::cout << "PQC key established.\n";
    std::cout << "DEBUG: PQC shared secret(hex) = " << to_hex_snippet(pqc_material.shared_secret) << std::endl;
    std::cout << "DEBUG: PQC ciphertext(hex) = " << to_hex_snippet(pqc_material.ciphertext) << std::endl;

    ECDHKeyMaterial ecdh_material = PerformECDHKeyExchange(new_socket);
    if (ecdh_material.shared_secret.empty())
    {
        std::cerr << "Server: ECDH key derivation failed.\n";
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

        std::cout << "Session key established: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
    else
    {
        std::string buffer_str = get_qkdkey(qkd_ip, new_socket);
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

        std::cout << "Session key established: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
}

void handle_client(boost::asio::io_context &io_context, tcp::socket tcp_socket, int tundesc, const std::string &chosen_pqc_alg, const std::string &qkd_ip)
{
    std::vector<unsigned char> aes_keys;
    udp::socket udp_socket(io_context);

    try
    {
        std::cout << "New client connected: " << tcp_socket.remote_endpoint().address() << "\n";

        const std::string ready_msg = "READY";
        boost::asio::write(tcp_socket, boost::asio::buffer(ready_msg));
        std::cout << "READY sent to client\n";

        // Robustly handle the initial "INIT_REKEY" message
        const std::string expected_init_msg = "INIT_REKEY";
        std::vector<char> init_buf(expected_init_msg.length());
        boost::system::error_code ec;
        // Use boost::asio::read to ensure we read exactly the expected number of bytes.
        size_t init_len = boost::asio::read(tcp_socket, boost::asio::buffer(init_buf), ec);
        if (ec)
        {
            std::cerr << "Error during initial INIT_REKEY read: " << ec.message() << "\n";
            tcp_socket.close();
            return;
        }
        if (init_len == 0)
        {
            std::cerr << "Client closed connection before sending INIT_REKEY\n";
            tcp_socket.close();
            return;
        }

        std::string init_msg(init_buf.begin(), init_buf.end());
        if (init_msg == expected_init_msg)
        {
            aes_keys = rekey_srv(tcp_socket, qkd_ip, chosen_pqc_alg);
            std::cout << "Initial rekey done, keys established\n";
        }
        else
        {
            std::cerr << "Unexpected initial command: " << init_msg << "\n";
            tcp_socket.close();
            return;
        }

        if (aes_keys.size() < AES_GCM_KEY_LEN * 2)
        {
            std::cerr << "Key establishment failed or keys are too short. Closing connection.\n";
            tcp_socket.close();
            return;
        }

        // Create a dedicated UDP socket for this client on an ephemeral port
        udp_socket.open(udp::v4());
        udp_socket.bind(udp::endpoint(udp::v4(), 0));
        udp::endpoint client_udp_ep;
        unsigned short udp_port = udp_socket.local_endpoint().port();
        std::cout << "Client " << tcp_socket.remote_endpoint().address()
                  << " assigned to dedicated UDP port: " << udp_port << std::endl;

        // Send the new UDP port to the client over TCP
        std::string port_msg = std::to_string(udp_port);
        send_framed_message(tcp_socket, port_msg);

        // Now perform the handshake on the dedicated socket (can be blocking)

        char udp_buf[1024];
        // This initial UDP handshake should be blocking to ensure it completes.
        // However, the TCP socket should be non-blocking for the main loop later.
        udp_socket.non_blocking(false);

        size_t len = udp_socket.receive_from(boost::asio::buffer(udp_buf), client_udp_ep);
        std::cout << "Server received UDP: " << std::string(udp_buf, len) << "\n";

        std::string reply = "Hello from server UDP";
        udp_socket.send_to(boost::asio::buffer(reply), client_udp_ep);
        std::cout << "Server replied to UDP\n";

        // Now, set sockets to non-blocking for the main select() loop.
        boost::system::error_code non_blocking_ec;
        tcp_socket.non_blocking(true, non_blocking_ec);
        udp_socket.non_blocking(true, non_blocking_ec);

        std::atomic<int> read_order(1), send_order(1);
        std::vector<unsigned char> key_decrypt(aes_keys.begin(), aes_keys.begin() + AES_GCM_KEY_LEN);
        std::vector<unsigned char> key_encrypt(aes_keys.begin() + AES_GCM_KEY_LEN, aes_keys.end());

        const std::chrono::seconds keepalive_interval(15);
        auto last_udp_send_time = std::chrono::steady_clock::now();
        const std::string keepalive_msg_to_client = "KEEPALIVE_S";

        while (true)
        {
            fd_set fds;
            FD_ZERO(&fds);

            int tcp_native = tcp_socket.native_handle();
            FD_SET(tcp_native, &fds);

            int udp_native = udp_socket.native_handle();
            FD_SET(udp_native, &fds);

            FD_SET(tundesc, &fds);

            int max_fd = std::max({tundesc, tcp_native, udp_native});

            struct timeval tv = {1, 0}; // 1 second timeout for keepalives
            int ret = select(max_fd + 1, &fds, NULL, NULL, &tv);

            if (ret < 0) {
                perror("select() error");
                break;
            }

            // 1. Process TCP commands (if select indicated activity)
            if (FD_ISSET(tcp_native, &fds)) {
                try {
                    std::string cmd = receive_framed_message(tcp_socket);
                    if (cmd == "REKEY_CLIENT_INITIATED") {
                        std::cout << "Client initiated rekey" << std::endl;
                        
                        tcp_socket.non_blocking(false, non_blocking_ec);
                        aes_keys = rekey_srv(tcp_socket, qkd_ip, chosen_pqc_alg);
                        tcp_socket.non_blocking(true, non_blocking_ec);

                        if (aes_keys.size() >= AES_GCM_KEY_LEN * 2) {
                            key_decrypt.assign(aes_keys.begin(), aes_keys.begin() + AES_GCM_KEY_LEN);
                            key_encrypt.assign(aes_keys.begin() + AES_GCM_KEY_LEN, aes_keys.end());
                            std::cout << "Rekey completed & keys updated" << std::endl;
                        } else {
                            std::cerr << "Rekey returned insufficient key material. Closing connection.\n";
                            break;
                        }
                    }
                } catch (const boost::system::system_error &e) {
                    if (e.code() == boost::asio::error::eof || e.code() == boost::asio::error::connection_reset) {
                        std::cerr << "TCP connection closed by peer.\n";
                    } else if (e.code() != boost::asio::error::would_block) {
                        std::cerr << "TCP error: " << e.what() << "\n";
                    }
                    break; // Exit loop on TCP error/closure
                }
            }

            // 2. Process TUN->UDP traffic
            if (FD_ISSET(tundesc, &fds)) {
                if (E_N_C_R(udp_socket, client_udp_ep, key_encrypt, tundesc, read_order, send_order)) {
                    last_udp_send_time = std::chrono::steady_clock::now();
                }
            }

            // 3. Process UDP->TUN traffic
            if (FD_ISSET(udp_native, &fds)) {
                D_E_C_R(udp_socket, client_udp_ep, key_decrypt, tundesc, read_order, send_order);
            }

            // 4. Handle keep-alive if select timed out
            if (ret == 0) {
                auto now = std::chrono::steady_clock::now();
                if (now - last_udp_send_time > keepalive_interval) {
                    udp_socket.send_to(boost::asio::buffer(keepalive_msg_to_client), client_udp_ep);
                    last_udp_send_time = now;
                }
            }
        }
        tcp_socket.close();
        udp_socket.close();
    }



    catch (const std::exception &e)
    {
        std::cerr << "Server exception: " << e.what() << "\n";
    }
    // Ensure sockets are closed if an exception occurs, and log thread completion.
    if (tcp_socket.is_open()) tcp_socket.close();
    if (udp_socket.is_open()) udp_socket.close();
    std::cout << "Client thread finished. Cleaning up." << std::endl;
   
}


int main(int argc, char *argv[])
{
    std::string qkd_ip;
    if (argc > 2)
    {
        help();
        return 1;
    }
    if (argc == 2)
    {
        qkd_ip = argv[1];
    }

    if (!OPENSSL_init_crypto(0, nullptr))
        return 1;
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(nullptr, "default");

    int choice;
    std::string chosen_pqc_alg;
    std::cout << "Choose PQC Algorithm:\n1. MLKEM768 (Kyber768)\n2. HQC-128\nEnter choice: ";
    std::cin >> choice;
    switch (choice)
    {
    case 1:
        chosen_pqc_alg = "ML-KEM-768";
        break;
    case 2:
        chosen_pqc_alg = "hqc-128";
        break;
    default:
        std::cerr << "Invalid choice, defaulting to Kyber768\n";
        chosen_pqc_alg = "ML-KEM-768";
        break;
    }
    std::cout << "Selected PQC Algorithm: " << chosen_pqc_alg << std::endl;

    // --- TUN device setup ---
    // The TUN device is created once and shared by all client threads.
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

    try
    {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), KEYPORT));
        std::cout << "Server TCP listening on port " << KEYPORT << std::endl;
        
        std::list<std::thread> client_threads; // Use std::list for efficient removal

        while (true)
        {
            tcp::socket socket(io_context);
            acceptor.accept(socket);

            client_threads.emplace_back(
                [&io_context, s = std::move(socket), tundesc, chosen_pqc_alg, qkd_ip]() mutable
                {
                    handle_client(io_context, std::move(s), tundesc, chosen_pqc_alg, qkd_ip);
                });
        }

        // On graceful shutdown (e.g. Ctrl-C), join all remaining threads.
        for (auto &t : client_threads) {
            if (t.joinable()) {
                t.join();
            }
        }
    }
    catch (const std::exception &e)
    {
        std::cerr << "Server exception: " << e.what() << std::endl;
        return 1;
    }

    if (tundesc != -1)
    {
        close(tundesc);
    }

    if (defprov)
        OSSL_PROVIDER_unload(defprov);
    return 0;
}
