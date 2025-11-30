#include <thread>
#include <atomic>
#include <ctime>
#include <utility>        // For std::exchange, must be before asio
#include <boost/asio.hpp> // Include Boost.Asio before system network headers
#include <signal.h>
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
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/provider.h>
#include <openssl/rand.h>
#include <stdexcept>
#include <string>
#include <cstring>
#include <cstdint>
#include <map> // Added for PQC algorithm properties
#include <iomanip>
#include <iterator>
#include <openssl/core_names.h>
#include <openssl/param_build.h>
#include <openssl/hmac.h>
#include <span>

using boost::asio::ip::tcp;
using boost::asio::ip::udp;
#include <openssl/objects.h>

constexpr size_t MLKEM768_PKEY_LEN = 1184;
constexpr size_t MLKEM768_SS_LEN = 32;
#define PORT 62000
#define KEYPORT 61000
#define MAXLINE 4096
#define AES_GCM_KEY_LEN 32
#define AES_GCM_IV_LEN 12
#define TAG_SIZE 16

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

string xy_str;
string kyber_cipher_data_str;
string qkd_parameter;
std::mutex m1;

/*
   Get encryption order after reading from tun interface
*/

int get_order(std::atomic<int> &read_order)
{
    m1.lock();
    read_order = (read_order % 100000) + 1;
    int order = read_order;
    m1.unlock();
    return order;
}

// Helper function to send a length-prefixed message
void send_framed_message(tcp::socket &socket, const std::string &msg)
{
    uint32_t msg_len = htonl(msg.length()); // Ensure network byte order
    boost::asio::write(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)));
    boost::asio::write(socket, boost::asio::buffer(msg));
}

// Helper function to receive a length-prefixed message
std::string receive_framed_message(tcp::socket &socket)
{
    uint32_t msg_len;
    boost::system::error_code ec;
    boost::asio::read(socket, boost::asio::buffer(&msg_len, sizeof(msg_len)), ec);
    if (ec)
    {
        throw boost::system::system_error(ec);
    }
    msg_len = ntohl(msg_len); // Convert from network to host byte order

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

    // Create SSL context
    ctx = SSL_CTX_new(SSLv23_client_method());
    if (ctx == NULL)
    {
        printf("Error while creating context.\n");
        exit(EXIT_FAILURE);
    }

    // Configure SSL context to use the certificate of the CA
    if (SSL_CTX_load_verify_locations(ctx, SERVER_CA_CERT, NULL) != 1)
    {
        printf("Error while loading a server CA certificate.\n");
        exit(EXIT_FAILURE);
    }

    // Create SSL connection
    ssl = SSL_new(ctx);
    if (ssl == NULL)
    {
        printf("Error while creating SSL connection.\n");
        exit(EXIT_FAILURE);
    }

    // Create BIO object
    bio = BIO_new_ssl_connect(ctx);
    if (bio == NULL)
    {
        printf("Error while creating BIO object.\n");
        exit(EXIT_FAILURE);
    }

    string hostname = srv_ip + string(":") + string("61000");
    // Set hostname
    BIO_set_conn_hostname(bio, hostname.c_str());

    // Connect BIO object to SSL
    BIO_get_ssl(bio, &ssl);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    // Open connection
    if (BIO_do_connect(bio) <= 0)
    {
        printf("Connection error.\n");
        exit(EXIT_FAILURE);
    }

    // Validate server certificate
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

    // Load server's certificate
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

    // Load CA certificate
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

    // Create X509_STORE and add CA certificate
    store = X509_STORE_new();
    if (!store || X509_STORE_add_cert(store, caCert) != 1)
    {
        perror("Error adding CA certificate to store");
        X509_free(serverCert);
        X509_free(caCert);
        X509_STORE_free(store);
        exit(EXIT_FAILURE);
    }

    // Set the trusted certificate store to verify against
    // Skipping the verification step that checks for a trusted issuer
    // X509_STORE_set_flags(store, X509_V_FLAG_ALLOW_SELF_SIGNED);
    // Create X509_STORE_CTX
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

    // Clean up
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

// Virtual interface access
int tun_open()
{
    struct ifreq ifr;
    int fd, err;

    if ((fd = open("/dev/net/tun", O_RDWR | O_NONBLOCK)) == -1)
    {
        perror("open /dev/net/tun");
        exit(1);
    }
    memset(&ifr, 0, sizeof(ifr));
    ifr.ifr_flags = IFF_TUN | IFF_NO_PI;
    strncpy(ifr.ifr_name, "tun0", IFNAMSIZ);

    if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) == -1)
    {
        perror("ioctl TUNSETIFF");
        close(fd);
        exit(1);
    }

    return fd;
}

// Encrypted data recieve
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

// Virtual interface data read
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

// Send encrypted data
void send_encrypted(udp::socket &socket, udp::endpoint &remote_endpoint, const string &cipher)
{
    socket.send_to(boost::asio::buffer(cipher), remote_endpoint);
}

// Data encryption
string encrypt_data(const std::vector<unsigned char> &key, const string &plaintext)
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int ciphertext_len;
    std::vector<unsigned char> iv(AES_GCM_IV_LEN);
    std::vector<unsigned char> ciphertext(plaintext.length());
    std::vector<unsigned char> tag(TAG_SIZE);

    // Generate a random IV
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

// Data decryption + integrity check
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
   Aggregation of functions needed for data recieve:
   1) Receive incoming encrypted data
   2) Decrypt data and check integrity
   3) Write decrypted data to virtual interface

   Returns false if there are no more data available on socket.
*/

bool D_E_C_R(udp::socket &socket, udp::endpoint &remote_endpoint, const std::vector<unsigned char> &key, int tundesc, std::atomic<int> &read_order, std::atomic<int> &send_order)
{
    string data;
    string encrypted_data = data_recieve(socket, remote_endpoint);
    // Encrypted data should be at least 33 char long (16B nonce, 16B auth tag)
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
   Aggregation of functions needed for encryption and data send:
   1) Read data from virtual interface
   2) Encrypt data
   3) Send encrypted data

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

// Thread function for both encryption and decryption
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
    // Use std::stringstream for efficient string construction
    std::stringstream ss;

    // Set formatting for uppercase hexadecimal output, padded with '0'
    ss << std::hex << std::uppercase << std::setfill('0');

    for (uint8_t byte : data)
    {
        // Cast to int is necessary to avoid treating uint8_t as a character
        // when streaming, ensuring it is formatted as a number.
        ss << std::setw(2) << (int)byte;
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

std::vector<uint8_t> hmac_hashing_bytes(const std::string &salt, const std::string &key)
{
    EVP_PKEY *pkey = EVP_PKEY_new_mac_key(EVP_PKEY_HMAC, nullptr,
                                          (const unsigned char *)salt.data(), salt.size());
    if (!pkey)
        return {};

    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        return {};
    }

    std::vector<uint8_t> digest(EVP_MAX_MD_SIZE);
    size_t digest_len = 0;

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha512(), nullptr, pkey) <= 0 ||
        EVP_DigestSignUpdate(ctx, (const unsigned char *)key.data(), key.size()) <= 0 ||
        EVP_DigestSignFinal(ctx, digest.data(), &digest_len) <= 0)
    {
        EVP_MD_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return {};
    }

    digest.resize(digest_len);
    EVP_MD_CTX_free(ctx);
    EVP_PKEY_free(pkey);

    return digest; // raw bytes
}

std::vector<uint8_t> sha3_hashing_bytes(const std::string &key, const std::string &public_value)
{
    std::string concat = public_value + key;

    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx)
        return {};

    unsigned char md_value[EVP_MAX_MD_SIZE];
    unsigned int md_len;

    EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr);
    EVP_DigestUpdate(mdctx, concat.data(), concat.size());
    EVP_DigestFinal_ex(mdctx, md_value, &md_len);
    EVP_MD_CTX_free(mdctx);

    return std::vector<uint8_t>(md_value, md_value + md_len); // raw bytes
}

std::vector<uint8_t> xorVectors(const std::vector<uint8_t> &a, const std::vector<uint8_t> &b)
{
    size_t n = std::min(a.size(), b.size());
    std::vector<uint8_t> result(n);
    for (size_t i = 0; i < n; i++)
        result[i] = a[i] ^ b[i];
    return result;
}

EVP_PKEY* create_pqc_pubkey_from_raw(const std::string& alg_name,
                                     const std::vector<unsigned char>& raw_pkey)
{
    EVP_PKEY* pkey = EVP_PKEY_new_raw_public_key_ex(
        /*libctx=*/NULL,
        alg_name.c_str(),     // "ML-KEM-768"
        /*propq=*/NULL,
        raw_pkey.data(),
        raw_pkey.size()
    );
    if (!pkey) {
        std::cerr << "Error: EVP_PKEY_new_raw_public_key_ex failed.\n";
        ERR_print_errors_fp(stderr);
        return nullptr;
    }
    return pkey;
}

// Struct to hold PQC algorithm properties
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

    // 1) Make sure the KEM exists
    EVP_KEM *kem = EVP_KEM_fetch(NULL, alg, NULL);
    if (!kem)
    {
        std::cerr << "EVP_KEM_fetch failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("KEM not present for: " + std::string(alg));
    }
    EVP_KEM_free(kem); // we only needed to check presence

    // 2) Generate a throwaway keypair via PKEY API
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    if (!pkey)
    {
        std::cerr << "EVP_PKEY_Q_keygen failed for '" << alg << "'\n";
        ERR_print_errors_fp(stderr);
        throw std::runtime_error("Failed to keygen for: " + std::string(alg));
    }

    // 3) Get public key length by exporting raw pubkey
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

    // 4) Trial encapsulation to discover ct + shared secret lengths
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

// --- THE UPDATED FUNCTION BLOCK ---

std::string get_pqckey(tcp::socket &client_socket, const std::string &alg_name)
{
    PQC_Alg_Properties props = get_pqc_alg_properties(alg_name);

    std::vector<uint8_t> server_pub(props.pubkey_len);
    std::vector<uint8_t> _shrd_key(props.shared_secret_len, 0);

    // 1. RECEIVE SERVER PUBKEY (framed)
    std::string server_pub_str = receive_framed_message(client_socket);
    server_pub.assign(server_pub_str.begin(), server_pub_str.end());
    std::cout << "Client DEBUG: received pubkey(hex) = " << to_hex(server_pub) << "\n";

    // 2. Create server PQC public key
    EVP_PKEY *server_pqc_pubkey = create_pqc_pubkey_from_raw(alg_name, server_pub);
    if (!server_pqc_pubkey)
    {
        return "Error: Failed to import server public key.";
    }

    // 3. ENCAPSULATE
    EVP_PKEY_CTX *ctx_encap = EVP_PKEY_CTX_new_from_pkey(NULL, server_pqc_pubkey, NULL);
    if (!ctx_encap || 1 != EVP_PKEY_encapsulate_init(ctx_encap, NULL))
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_encap);
        EVP_PKEY_free(server_pqc_pubkey);
        return "Error: Encapsulate init failed.";
    }

    size_t ciphertext_len = 0;
    size_t shared_secret_len = 0;
    if (1 != EVP_PKEY_encapsulate(ctx_encap, NULL, &ciphertext_len, NULL, &shared_secret_len))
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_encap);
        EVP_PKEY_free(server_pqc_pubkey);
        return "Error: Failed to get lengths for encapsulation.";
    }

    std::vector<unsigned char> _cipher(ciphertext_len);
    _shrd_key.resize(shared_secret_len);

    if (1 != EVP_PKEY_encapsulate(ctx_encap,
                                  _cipher.data(), &ciphertext_len,
                                  _shrd_key.data(), &shared_secret_len))
    {
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(ctx_encap);
        EVP_PKEY_free(server_pqc_pubkey);
        return "Error: Encapsulation failed.";
    }

    EVP_PKEY_CTX_free(ctx_encap);

    // 4. SEND CIPHERTEXT (framed)
    std::string cipher_str(_cipher.begin(), _cipher.end());
    send_framed_message(client_socket, cipher_str);

    // 5. HEX ENCODE SHARED SECRET
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : _shrd_key)
        ss << std::setw(2) << (int)byte;

    EVP_PKEY_free(server_pqc_pubkey);
    return ss.str();
}

// Program usage help
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

std::string PerformECDHKeyExchange(tcp::socket &sock)
{
    EVP_PKEY *client_key = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY *peer_key = nullptr;
    unsigned char *shared_secret = nullptr;
    size_t shared_secret_len = 0;
    std::string final_shared_secret_hex;

    // 1) Generate client's ECDH key pair (secp521r1)
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
        return "";
    }
    EVP_PKEY_CTX_free(pctx);
    pctx = nullptr;

    // 2) Export client's raw public key (octet string)
    size_t client_pub_len = 0;
    if (EVP_PKEY_get_octet_string_param(client_key, OSSL_PKEY_PARAM_PUB_KEY, NULL, 0, &client_pub_len) != 1)
    {
        std::cerr << "Error: EVP_PKEY_get_octet_string_param (len) failed for client pubkey." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        return "";
    }
    std::vector<unsigned char> client_pub(client_pub_len);
    if (EVP_PKEY_get_octet_string_param(client_key, OSSL_PKEY_PARAM_PUB_KEY,
                                        client_pub.data(), client_pub.size(), &client_pub_len) != 1)
    {
        std::cerr << "Error: EVP_PKEY_get_octet_string_param (export) failed for client pubkey." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        return "";
    }

    // Optional debug
    std::cout << "Client DEBUG: sending ECDH pub len=" << client_pub.size() << std::endl;
    if (!client_pub.empty())
    {
        std::cout << "Client DEBUG: client_pub[0]=0x" << std::hex << std::uppercase << (int)client_pub[0]
                  << std::dec << " (expect 0x04)\n";
        size_t dump = std::min<size_t>(32, client_pub.size());
        std::vector<uint8_t> snippet(client_pub.begin(), client_pub.begin() + dump);
        std::cout << "Client DEBUG: client_pub snippet(hex) = " << to_hex(snippet) << std::endl;
    }

    // 3) Send client's public key (framed)
    try
    {
        send_framed_message(sock, std::string(client_pub.begin(), client_pub.end()));
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to send client's public key: " << e.what() << std::endl;
        EVP_PKEY_free(client_key);
        return "";
    }

    // 4) Receive server's public key (framed)
    std::string server_pub_str;
    try
    {
        server_pub_str = receive_framed_message(sock);
    }
    catch (const std::exception &e)
    {
        std::cerr << "Error: Failed to receive server's public key: " << e.what() << std::endl;
        EVP_PKEY_free(client_key);
        return "";
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

    // Basic sanity check: length should be 133 for secp521r1 uncompressed
    const size_t expected_len = 1 + 2 * ((521 + 7) / 8); // 133
    if (server_pub.size() != expected_len)
    {
        std::cerr << "Error: Unexpected server public key length: got " << server_pub.size()
                  << " expected " << expected_len << std::endl;
        EVP_PKEY_free(client_key);
        return "";
    }

    // 5) Create peer EVP_PKEY from server raw EC point using EVP_PKEY_fromdata
    EVP_PKEY_CTX *fromctx = EVP_PKEY_CTX_new_from_name(NULL, "EC", NULL);
    if (!fromctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_name(NULL, \"EC\", NULL) failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(client_key);
        return "";
    }
    if (EVP_PKEY_fromdata_init(fromctx) != 1)
    {
        std::cerr << "Error: EVP_PKEY_fromdata_init failed\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(fromctx);
        EVP_PKEY_free(client_key);
        return "";
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
        return "";
    }
    EVP_PKEY_CTX_free(fromctx);

    // 6) Derive shared secret
    EVP_PKEY_CTX *dctx = EVP_PKEY_CTX_new_from_pkey(NULL, client_key, NULL);
    if (!dctx)
    {
        std::cerr << "Error: EVP_PKEY_CTX_new_from_pkey for derive failed." << std::endl;
        ERR_print_errors_fp(stderr);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return "";
    }

    if (EVP_PKEY_derive_init(dctx) <= 0 ||
        EVP_PKEY_derive_set_peer(dctx, peer_key) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_derive_init or set_peer failed.\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return "";
    }

    if (EVP_PKEY_derive(dctx, NULL, &shared_secret_len) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_derive (len) failed.\n";
        ERR_print_errors_fp(stderr);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return "";
    }

    shared_secret = (unsigned char *)OPENSSL_malloc(shared_secret_len);
    if (!shared_secret)
    {
        std::cerr << "Error: OPENSSL_malloc failed\n";
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return "";
    }

    if (EVP_PKEY_derive(dctx, shared_secret, &shared_secret_len) <= 0)
    {
        std::cerr << "Error: EVP_PKEY_derive failed\n";
        ERR_print_errors_fp(stderr);
        OPENSSL_free(shared_secret);
        EVP_PKEY_CTX_free(dctx);
        EVP_PKEY_free(peer_key);
        EVP_PKEY_free(client_key);
        return "";
    }

    // 7) Hex encode shared secret
    std::vector<uint8_t> secret_vec(shared_secret, shared_secret + shared_secret_len);
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : secret_vec)
        ss << std::setw(2) << (int)byte;
    final_shared_secret_hex = ss.str();

    // 8) Cleanup
    OPENSSL_free(shared_secret);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(client_key);

    return final_shared_secret_hex;
}

string xorStrings(const string &str1, const string &str2)
{
    // Handle hex strings by converting to bytes, XORing, then converting back
    std::vector<uint8_t> bytes1 = hex_to_bytes(str1);
    std::vector<uint8_t> bytes2 = hex_to_bytes(str2);

    size_t len = std::min(bytes1.size(), bytes2.size());
    std::vector<uint8_t> result_bytes;
    result_bytes.reserve(len);

    for (size_t i = 0; i < len; ++i)
    {
        result_bytes.push_back(bytes1[i] ^ bytes2[i]);
    }

    // Use the global to_hex logic
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
    // buffer to string
    string buffer_str = buffer.str();

    std::ifstream s("keyID");
    std::stringstream bufferTCP;
    bufferTCP << s.rdbuf();
    // bufferTCP to string
    string bufferTCP_str = bufferTCP.str();
    cout << "KeyID: " << bufferTCP_str << endl;

    // Hash content of bufferTCP with SHAKE128 using OpenSSL
    std::vector<unsigned char> shake_output(216);
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    if (!mdctx) { /* handle error */ return ""; }

    const EVP_MD *shake128 = EVP_shake128();
    EVP_DigestInit_ex(mdctx, shake128, NULL);
    EVP_DigestUpdate(mdctx, bufferTCP.str().c_str(), bufferTCP.str().length());
    EVP_DigestFinalXOF(mdctx, shake_output.data(), shake_output.size());
    EVP_MD_CTX_free(mdctx);

    // Use the global to_hex logic
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');
    for (unsigned char byte : shake_output)
    {
        ss << std::setw(2) << (int)byte;
    }
    string pom_param = ss.str();

    // The original logic had a potential issue with non-printable characters.
    qkd_parameter = pom_param + bufferTCP_str.substr(0, 216);

    boost::asio::write(client_socket, boost::asio::buffer(bufferTCP_str));
    cout << "QKD key established:" << buffer_str << endl;

    return buffer_str;
}

/*
   Rekeying - client mode

   Client get new key from QKD server, combine it with PQC key
   and than send its ID to gateway in server mode.
*/
std::vector<unsigned char> rekey_cli(tcp::socket &client_socket, string qkd_ip, const char *srv_ip, string buffer_str, const std::string &chosen_pqc_alg)
{
    std::vector<unsigned char> digest(EVP_MD_size(EVP_sha512()));
    std::vector<unsigned char> sec_key(AES_GCM_KEY_LEN * 2);

    // Receive the session salt from the server (framed)
    std::string salt = receive_framed_message(client_socket);
    std::cout << "Received salt from server." << std::endl;

    // PQC key (framed)
    std::string pqc_key = get_pqckey(client_socket, chosen_pqc_alg);
    std::cout << "PQC key: " << pqc_key << std::endl;

    // sleep for QKD
    // std::this_thread::sleep_for(std::chrono::seconds(90));

    // ECDH key (framed)
    std::string ecdh_key = PerformECDHKeyExchange(client_socket);
    std::cout << "ECDH key: " << ecdh_key << std::endl;
    if (qkd_ip.empty())
    {
        // First-round HMAC keys
        auto key_one = hmac_hashing_bytes(salt, pqc_key);
        auto key_two = hmac_hashing_bytes(salt, ecdh_key);

        // SHA3-512 parameters
        auto param_one = sha3_hashing_bytes(pqc_key, kyber_cipher_data_str);
        auto param_two = sha3_hashing_bytes(ecdh_key, xy_str);

        // Second-round HMAC keys
        auto second_round_key_one = hmac_hashing_bytes(std::string(param_one.begin(), param_one.end()),
                                                       std::string(key_one.begin(), key_one.end()));
        auto second_round_key_two = hmac_hashing_bytes(std::string(param_two.begin(), param_two.end()),
                                                       std::string(key_two.begin(), key_two.end()));

        // XOR to hybrid key
        auto hybrid_key = xorVectors(second_round_key_one, second_round_key_two);

        // SHA3-512 final digest
        std::vector<uint8_t> digest(EVP_MD_size(EVP_sha3_512()));
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr);
        EVP_DigestUpdate(mdctx, hybrid_key.data(), hybrid_key.size());
        unsigned int digest_len;
        EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len);
        EVP_MD_CTX_free(mdctx);
        digest.resize(digest_len);

        // Copy safely into session key
        if (sec_key.size() > digest.size())
            throw std::runtime_error("Session key buffer too large for derived key");
        std::copy_n(digest.begin(), sec_key.size(), sec_key.begin());

        // Cleanse sensitive memory
        OPENSSL_cleanse(digest.data(), digest.size());
        OPENSSL_cleanse(hybrid_key.data(), hybrid_key.size());
        hybrid_key.assign(hybrid_key.size(), '\0');
        std::cout << "Session key: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
    else
    {   
        std::string qkd_key_buffer;
        qkd_key_buffer = get_qkdkey(qkd_ip, tcp_socket);
        // Include third QKD key
        auto key_one = hmac_hashing_bytes(salt, pqc_key);
        auto key_two = hmac_hashing_bytes(salt, ecdh_key);
        auto key_three = hmac_hashing_bytes(salt, buffer_str);

        auto param_one = sha3_hashing_bytes(pqc_key, kyber_cipher_data_str);
        auto param_two = sha3_hashing_bytes(ecdh_key, xy_str);
        auto param_three = sha3_hashing_bytes(buffer_str, qkd_parameter);

        auto second_round_key_one = hmac_hashing_bytes(std::string(param_two.begin(), param_two.end()),
                                                       std::string(key_one.begin(), key_one.end()));
        auto second_round_key_two = hmac_hashing_bytes(std::string(param_one.begin(), param_one.end()),
                                                       std::string(key_two.begin(), key_two.end()));
        auto second_round_key_three = hmac_hashing_bytes(std::string(param_one.begin(), param_one.end()) +
                                                             std::string(param_two.begin(), param_two.end()),
                                                         std::string(key_three.begin(), key_three.end()));

        auto hybrid_key = xorVectors(xorVectors(second_round_key_one, second_round_key_two), second_round_key_three);

        std::vector<uint8_t> digest(EVP_MD_size(EVP_sha3_512()));
        EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
        EVP_DigestInit_ex(mdctx, EVP_sha3_512(), nullptr);
        EVP_DigestUpdate(mdctx, hybrid_key.data(), hybrid_key.size());
        unsigned int digest_len;
        EVP_DigestFinal_ex(mdctx, digest.data(), &digest_len);
        EVP_MD_CTX_free(mdctx);
        digest.resize(digest_len);

        if (sec_key.size() > digest.size())
            throw std::runtime_error("Session key buffer too large for derived key");
        std::copy_n(digest.begin(), sec_key.size(), sec_key.begin());

        OPENSSL_cleanse(digest.data(), digest.size());
        OPENSSL_cleanse(hybrid_key.data(), hybrid_key.size());
        hybrid_key.assign(hybrid_key.size(), '\0');
        std::cout << "Session key: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
}

int main(int argc, char* argv[]) {
    if (argc < 1 || argc > 3) {
        help();
        return 1; 
    }
    const char* srv_ip = argv[1];
    std::string qkd_ip;
    if (argc == 3) {
        qkd_ip = argv[2];
    }
    // --- PQC Algorithm Selection Menu ---
    int choice;
    std::string chosen_pqc_alg;
    std::cout << "Choose PQC Algorithm:\n1. MLKEM768 (Kyber768)\n2. HQC-128\nEnter choice: ";
    std::cin >> choice;
    switch (choice) {
        case 1: chosen_pqc_alg = "ML-KEM-768"; break;
        case 2: chosen_pqc_alg = "hqc-128"; break;
        default: std::cerr << "Invalid choice, defaulting to Kyber768\n"; chosen_pqc_alg = "ML-KEM-768"; break;
    }
    std::cout << "Selected PQC Algorithm: " << chosen_pqc_alg << std::endl;

    while (true) {
        try {
            boost::asio::io_context io_context;
            tcp::socket tcp_socket(io_context);
            tcp::resolver resolver(io_context);
            boost::asio::connect(tcp_socket, resolver.resolve(srv_ip, std::to_string(KEYPORT)));
            std::cout << "Connected to server\n";

            // --- Wait for READY from server ---
            char ready_buf[5] = {0};
            boost::asio::read(tcp_socket, boost::asio::buffer(ready_buf, 5));
            std::cout << "Server READY received\n";

            // --- Trigger and perform initial rekey (BEFORE UDP handshake) ---
            const std::string init_rekey_msg = "INIT_REKEY";
            boost::asio::write(tcp_socket, boost::asio::buffer(init_rekey_msg));
            
            std::vector<uint8_t> sec_key;
            if (!qkd_ip.empty()) {
                sec_key = rekey_cli(tcp_socket, qkd_ip, srv_ip, qkd_key_buffer, chosen_pqc_alg);
            }
            else {
                sec_key = rekey_cli(tcp_socket, "", srv_ip, "", chosen_pqc_alg);
            }
            
            std::vector<unsigned char> key_encrypt(sec_key.begin(), sec_key.begin() + AES_GCM_KEY_LEN);
            std::vector<unsigned char> key_decrypt(sec_key.begin() + AES_GCM_KEY_LEN, sec_key.end());
            std::cout << "Initial rekey done, keys established\n";

            // --- Now, open UDP socket and handshake ---
            udp::socket udp_socket(io_context);
            udp::resolver udp_resolver(io_context);
            udp::endpoint server_udp_ep = *udp_resolver.resolve(udp::v4(), srv_ip, std::to_string(PORT)).begin();
            udp_socket.open(udp::v4());

            udp_socket.send_to(boost::asio::buffer("Hello from client UDP"), server_udp_ep);
            std::cout << "Client UDP hello sent\n";

            char udp_reply[1024] = {0};
            udp::endpoint server_reply_ep;
            udp_socket.receive_from(boost::asio::buffer(udp_reply), server_reply_ep);
            std::cout << "Received UDP reply from server: " << std::string(udp_reply) << "\n";
            udp_socket.non_blocking(true);

            tcp_socket.non_blocking(true); // Set TCP socket to non-blocking for the main loop
            // --- Threading and tun interface ---
            std::atomic<int> read_order = 0, send_order = 1;
            int tundesc = tun_open();
            int threads_max = std::thread::hardware_concurrency() > 1 ? std::thread::hardware_concurrency() - 1 : 1;
            std::atomic<int> threads_available = threads_max;

            std::atomic<bool> client_rekey_flag{false};
            std::thread([&client_rekey_flag]() {
                while (true) {
                    std::this_thread::sleep_for(std::chrono::hours(1));
                    client_rekey_flag.store(true);
                }
            }).detach();

            // --- Main loop: encryption/decryption and rekey handling ---
            while (true) {
                // TCP check
                boost::system::error_code ec;
                char tcp_buf[1024] = {0};
                size_t len = tcp_socket.read_some(boost::asio::buffer(tcp_buf), ec);
                if (!ec && len > 0) {
                    if (std::string(tcp_buf, len) == "REKEY_SERVER_INITIATED") {
                        std::string qkd_key_buffer;
                        if (!qkd_ip.empty()) {
                            qkd_key_buffer = get_qkdkey(qkd_ip, tcp_socket);
                            sec_key = rekey_cli(tcp_socket, qkd_ip, srv_ip, qkd_key_buffer, chosen_pqc_alg);
                        }
                        else {
                            sec_key = rekey_cli(tcp_socket, "", srv_ip, "", chosen_pqc_alg);
                        }

                        key_encrypt.assign(sec_key.begin(), sec_key.begin() + AES_GCM_KEY_LEN);
                        key_decrypt.assign(sec_key.begin() + AES_GCM_KEY_LEN, sec_key.end());
                        std::cout << "Server-initiated rekey completed\n";
                    }
                } else if (ec != boost::asio::error::would_block) {
                    std::cerr << "TCP connection error or closed: " << ec.message() << "\n";
                    break; // Exit loop on error
                }

                // Client-initiated rekey
                if (client_rekey_flag.load()) {
                    boost::asio::write(tcp_socket, boost::asio::buffer("REKEY_CLIENT_INITIATED"));
                    client_rekey_flag.store(false);

                    std::string qkd_key_buffer;
                    if (!qkd_ip.empty()) {
                        qkd_key_buffer = get_qkdkey(qkd_ip, tcp_socket);
                        sec_key = rekey_cli(tcp_socket, qkd_ip, srv_ip, qkd_key_buffer, chosen_pqc_alg);
                    }
                    else {
                        sec_key = rekey_cli(tcp_socket, "", srv_ip, "", chosen_pqc_alg);
                    }

                    key_encrypt.assign(sec_key.begin(), sec_key.begin() + AES_GCM_KEY_LEN);
                    key_decrypt.assign(sec_key.begin() + AES_GCM_KEY_LEN, sec_key.end());
                    std::cout << "Client-initiated rekey completed\n";
                }

                // Encryption/decryption
                if (E_N_C_R(udp_socket, server_udp_ep, key_encrypt, tundesc, read_order, send_order) ||
                    D_E_C_R(udp_socket, server_udp_ep, key_decrypt, tundesc, read_order, send_order)) {
                    if (threads_available > 0) {
                        threads_available -= 1;
                        std::thread(thread_encrypt, &udp_socket, server_udp_ep, &key_encrypt, &key_decrypt,
                                    tundesc, &threads_available, &read_order, &send_order).detach();
                    }
                }

                // If no work was done, pause briefly to prevent busy-spinning
                if (threads_available == threads_max) {
                    fd_set fds;
                    FD_ZERO(&fds);
                    FD_SET(tundesc, &fds);
                    int udp_native = udp_socket.native_handle();
                    FD_SET(udp_native, &fds);
                    struct timeval tv = {0, 1000}; // 1ms timeout
                    int max_fd = std::max(tundesc, udp_native);
                    // Wait for activity on tun or udp socket
                    select(max_fd + 1, &fds, NULL, NULL, &tv);
                }
            }

            tcp_socket.close();
            udp_socket.close();
        } catch (const std::exception &e) {
            std::cerr << "Client exception: " << e.what() << "\nRetrying in 5s...\n";
            std::this_thread::sleep_for(std::chrono::seconds(5));
        }
    }

    return 0;
}
