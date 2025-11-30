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

// Helper to print a snippet of a binary vector in hex for debugging
std::string to_hex_snippet(const std::vector<uint8_t>& data, size_t len = 32);

// Forward declarations for KDF helpers
std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data);
std::vector<uint8_t> sha3_512(const std::vector<uint8_t>& data);

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

void cert_authenticate_online()
{
    int counter = 0;

    SSL_CTX *ctx;
    SSL *ssl;
    BIO *acc, *client;

    // Create a new SSL context
    ctx = SSL_CTX_new(SSLv23_server_method());
    if (ctx == NULL)
    {
        printf("Error while creating context\n");
        exit(EXIT_FAILURE);
    }

    // Load the CA certificate
    if (SSL_CTX_load_verify_locations(ctx, CLIENT_CA_CERT, NULL) != 1)
    {
        printf("Error loading a client CA certificate.\n");
        exit(EXIT_FAILURE);
    }

    // Create BIO acceptor
    acc = BIO_new_accept("61000");
    if (acc == NULL)
    {
        printf("Error creating BIO acceptor.\n");
        exit(EXIT_FAILURE);
    }

    // Add acceptor to context
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

        // Acquiering client BIO
        client = BIO_pop(acc);
        if (client == NULL)
        {
            printf("Error acquiring client BIO.\n");
            exit(EXIT_FAILURE);
        }

        // Create new SSL connection state
        ssl = SSL_new(ctx);
        if (ssl == NULL)
        {
            printf("Error while creating SSL connection.\n");
            exit(EXIT_FAILURE);
        }

        // Connect the SSL object with the BIO
        SSL_set_bio(ssl, client, client);

        // Establish the SSL connection
        if (SSL_accept(ssl) <= 0)
        {
            printf("Error when establishing SSL connection.\n");
            exit(EXIT_FAILURE);
        }

        // Veryfying the certificate
        if (SSL_get_verify_result(ssl) != X509_V_OK)
        {
            printf("Error while verifying the certificate.\n");
            exit(EXIT_FAILURE);
        }

        // Shutdown the SSL connection
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

    // Perform certificate verification
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

std::string to_hex_snippet(const std::vector<uint8_t>& data, size_t len) {
    std::stringstream ss;
    ss << std::hex << std::uppercase << std::setfill('0');

    size_t count = std::min(data.size(), len);
    for (size_t i = 0; i < count; ++i) {
        ss << std::setw(2) << static_cast<int>(data[i]);
    }
    if (data.size() > len) {
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
        // Hex string must have an even length to represent whole bytes
        throw std::invalid_argument("Hex string must have an even length.");
    }

    std::vector<uint8_t> bytes;
    // Pre-allocate memory for efficiency
    bytes.reserve(hex.length() / 2);

    for (size_t i = 0; i < hex.length(); i += 2)
    {
        // Extract the two-character byte string
        std::string byteString = hex.substr(i, 2);

        // strtol converts the string to a long integer, specifying base 16 (hex).
        // nullptr is used for the end pointer as we only care about the first two characters.
        long value = std::strtol(byteString.c_str(), nullptr, 16);

        // Convert the result back to an 8-bit unsigned integer (uint8_t)
        bytes.push_back(static_cast<uint8_t>(value));
    }

    return bytes;
}

std::vector<uint8_t> hmac_sha512(const std::vector<uint8_t>& key, const std::vector<uint8_t>& data)
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

std::vector<uint8_t> sha3_512(const std::vector<uint8_t>& data) {
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
    // alg_name should be "ML-KEM-768"
    const char *alg = alg_name.c_str();

    // 1) Generate keypair via convenience API
    EVP_PKEY *pkey = EVP_PKEY_Q_keygen(NULL, NULL, alg);
    if (!pkey)
    {
        std::cerr << "generate_pqc_keypair: EVP_PKEY_Q_keygen failed for " << alg << "\n";
        ERR_print_errors_fp(stderr);
        return nullptr;
    }

    // 2) Export raw public key to raw_pubkey
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

    // raw_pubkey now holds the exact bytes the client must receive.
    return pkey; // caller owns the EVP_PKEY*
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

// Struct to return multiple values from key exchanges
struct PQCKeyMaterial {
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> ciphertext;
};

struct ECDHKeyMaterial {
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> peer_pubkey;
    std::vector<uint8_t> own_pubkey;
};

// Server-side PQC key exchange
PQCKeyMaterial get_pqckey(tcp::socket &new_socket, const std::string &alg_name)
{
    PQC_Alg_Properties props = get_pqc_alg_properties(alg_name);

    EVP_PKEY *server_private_key = nullptr;
    std::vector<uint8_t> _shrd_key(props.shared_secret_len, 0);
    std::vector<unsigned char> raw_pubkey;

    // 1. Generate KEM keypair
    server_private_key = generate_pqc_keypair(alg_name, raw_pubkey);
    if (!server_private_key)
    {
        std::cerr << "Error: Failed to generate server keypair.\n";
        return {}; // Return empty struct on failure
    }

    // Optional sanity check
    if (raw_pubkey.size() != props.pubkey_len)
    {
        std::cerr << "Warning: raw_pubkey.size()=" << raw_pubkey.size()
                  << " != props.pubkey_len=" << props.pubkey_len << "\n";
    }
    std::cout << "Server DEBUG: pubkey(hex) = " << to_hex(raw_pubkey) << "\n";

    // 2. Send public key (framed)
    try
    {
        send_framed_message(new_socket, std::string(raw_pubkey.begin(), raw_pubkey.end()));
        std::cout << "Server: sent PQC public key.\n";
    }
    catch (...)
    {
        std::cerr << "Error: Failed to send public key.\n";
        EVP_PKEY_free(server_private_key);
        return {}; // Return empty struct on failure
    }

    // 3. Receive ciphertext (framed)
    std::string cipher_str = receive_framed_message(new_socket);
    std::vector<uint8_t> cipher_buf(cipher_str.begin(), cipher_str.end());

    std::cout << "Server DEBUG: received ciphertext len = " << cipher_buf.size() << "\n";
    std::cout << "Server DEBUG: received ciphertext(hex) = " << to_hex(cipher_buf) << "\n";

    // 4. Decapsulate to get shared secret
    if (!decapsulate_kyber768(server_private_key, cipher_buf, _shrd_key))
    {
        std::cerr << "Error: Kyber decapsulation failed.\n";
        EVP_PKEY_free(server_private_key);
        return {}; // Return empty struct on failure
    }
    std::cout << "Server DEBUG: PQC shared secret(hex) = " << to_hex_snippet(_shrd_key) << "\n";

    // 5. Cleanup
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
        return ""; // Handle error or no data
    }
    std::string bufferTCP(buffer, len);

    // Write received keyID to file
    std::ofstream myfile;
    myfile.open("keyID");
    myfile << bufferTCP;
    myfile.close();

    // Obtain QKD key with keyID
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

    // The original logic had a potential issue with non-printable characters.
    // Using hex representation is safer.
    qkd_parameter = pom_param + bufferTCP.substr(0, 216);

    std::ifstream key_file("key");
    std::stringstream key_buffer;
    key_buffer << key_file.rdbuf();
    cout << "QKD key established:" << key_buffer.str() << endl;
    return key_buffer.str();
}

// Program usage help
void help()
{
    cout << endl
         << "   Usage:" << endl
         << endl;
    cout << "   ./encryptor_server [QKD IP]" << endl;
    cout << "   QKD IP - Local QKD system IP address {x.x.x.x} (optional)" << endl
         << endl;
}

// ECDH key exchange
ECDHKeyMaterial PerformECDHKeyExchange(tcp::socket &sock)
{
    EVP_PKEY *server_key = nullptr;
    EVP_PKEY_CTX *pctx = nullptr;
    EVP_PKEY *peer_key = nullptr;
    unsigned char *shared_secret = nullptr;
    size_t shared_secret_len = 0;
    std::vector<uint8_t> final_shared_secret_bytes;

    // 1. Generate server's ECDH key pair (secp521r1)
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

    // 2. Get server's raw public key to send to client
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

    // 3. Receive client's public key (framed)
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

    // 4. Send server's public key (framed)
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

    // 5. Create peer's EVP_PKEY from client's raw EC point using EVP_PKEY_fromdata
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

    // Build params: group name + public key octet string
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

    // 6. Derive shared secret
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

    // 7. Convert shared secret to hex
    final_shared_secret_bytes.assign(shared_secret, shared_secret + shared_secret_len);

    // 8. Clean up
    OPENSSL_free(shared_secret);
    EVP_PKEY_CTX_free(dctx);
    EVP_PKEY_free(peer_key);
    EVP_PKEY_free(server_key);

    return {final_shared_secret_bytes, client_pub, server_pub};
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
   Rekeying - client mode

   Server gets new key from QKD server, combines it with PQC key
   and than send its ID to gateway in server mode.
*/

std::vector<unsigned char> rekey_srv(tcp::socket &new_socket, std::string qkd_ip, const std::string &chosen_pqc_alg)
{
    std::vector<unsigned char> sec_key(AES_GCM_KEY_LEN * 2);

    // 1) Generate fresh salt and send it as raw bytes (FRAMED)
    std::vector<uint8_t> salt_bytes(64);
    if (RAND_bytes(salt_bytes.data(), salt_bytes.size()) != 1)
    {
        std::cerr << "Error: Failed to generate salt for HMAC.\n";
        return {};
    }
    send_framed_message(new_socket, std::string(salt_bytes.begin(), salt_bytes.end()));
    std::cout << "Server: sent salt (len=" << salt_bytes.size() << ")\n";
    std::cout << "DEBUG: salt(hex) = " << to_hex(salt_bytes) << std::endl;

    // 2) PQC KEM: uses framing INSIDE get_pqckey
    //    (server sends framed pubkey, client responds with framed ciphertext)
    PQCKeyMaterial pqc_material = get_pqckey(new_socket, chosen_pqc_alg);
    if (pqc_material.shared_secret.empty())
    {
        std::cerr << "Server: PQC key derivation failed.\n";
        return {};
    }
    std::cout << "PQC key established.\n";
    std::cout << "DEBUG: PQC shared secret(hex) = " << to_hex_snippet(pqc_material.shared_secret) << std::endl;
    std::cout << "DEBUG: PQC ciphertext(hex) = " << to_hex_snippet(pqc_material.ciphertext) << std::endl;

    // wait for QKD / sync
    // std::this_thread::sleep_for(std::chrono::seconds(90));

    // 3) ECDH: uses framing INSIDE PerformECDHKeyExchange
    //    (client sends framed pubkey, server responds with framed pubkey)
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
        // --- KDF without QKD ---
        // K1 = HMAC(salt, pqc_secret)
        auto k1 = hmac_sha512(salt_bytes, pqc_material.shared_secret);
        // K2 = HMAC(salt, ecdh_secret)
        auto k2 = hmac_sha512(salt_bytes, ecdh_material.shared_secret);

        // P1 = SHA3(pqc_ciphertext || pqc_secret)
        std::vector<uint8_t> p1_input = pqc_material.ciphertext;
        p1_input.insert(p1_input.end(), pqc_material.shared_secret.begin(), pqc_material.shared_secret.end());
        auto p1 = sha3_512(p1_input);
        
        // P2 = SHA3(own_pub || peer_pub || ecdh_secret)
        std::vector<uint8_t> p2_input;
        // Symmetrize by sorting public keys before concatenation
        if (ecdh_material.own_pubkey < ecdh_material.peer_pubkey) {
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
        } else {
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
        }
        p2_input.insert(p2_input.end(), ecdh_material.shared_secret.begin(), ecdh_material.shared_secret.end());
        auto p2 = sha3_512(p2_input);

        // S1 = HMAC(P1, K1)
        auto s1 = hmac_sha512(p1, k1);
        // S2 = HMAC(P2, K2)
        auto s2 = hmac_sha512(p2, k2);

        // hybrid_key = XOR(S1, S2)
        auto hybrid_key = xorVectors(s1, s2);
        std::cout << "DEBUG: hybrid_key(hex) = " << to_hex_snippet(hybrid_key) << std::endl;

        // final_digest = SHA3(hybrid_key)
        auto final_digest = sha3_512(hybrid_key);
        std::cout << "DEBUG: final_digest(hex) = " << to_hex(final_digest) << std::endl;

        // Copy safely into session key, ensuring we don't read past the end of the digest
        if (sec_key.size() > final_digest.size()) {
             throw std::runtime_error("Session key buffer is larger than the derived digest.");
        }
        std::copy_n(final_digest.begin(), sec_key.size(), sec_key.begin());

        // Cleanse all intermediate sensitive material
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
        // --- KDF with QKD ---
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
        if (ecdh_material.own_pubkey < ecdh_material.peer_pubkey) {
            p2_input.insert(p2_input.end(), ecdh_material.own_pubkey.begin(), ecdh_material.own_pubkey.end());
            p2_input.insert(p2_input.end(), ecdh_material.peer_pubkey.begin(), ecdh_material.peer_pubkey.end());
        } else {
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

        if (sec_key.size() > final_digest.size()) {
             throw std::runtime_error("Session key buffer is larger than the derived digest.");
        }
        std::copy_n(final_digest.begin(), sec_key.size(), sec_key.begin());

        // Cleanse
        OPENSSL_cleanse(k1.data(), k1.size()); OPENSSL_cleanse(k2.data(), k2.size()); OPENSSL_cleanse(k3.data(), k3.size());
        OPENSSL_cleanse(p1.data(), p1.size()); OPENSSL_cleanse(p2.data(), p2.size()); OPENSSL_cleanse(p3.data(), p3.size());
        OPENSSL_cleanse(s1.data(), s1.size()); OPENSSL_cleanse(s2.data(), s2.size()); OPENSSL_cleanse(s3.data(), s3.size());
        OPENSSL_cleanse(hybrid_key.data(), hybrid_key.size());
        OPENSSL_cleanse(final_digest.data(), final_digest.size());
        OPENSSL_cleanse(pqc_material.shared_secret.data(), pqc_material.shared_secret.size());
        OPENSSL_cleanse(ecdh_material.shared_secret.data(), ecdh_material.shared_secret.size());
        OPENSSL_cleanse(qkd_key_bytes.data(), qkd_key_bytes.size());

        std::cout << "Session key established: " << to_hex(sec_key) << std::endl;

        return sec_key;
    }
}
void handle_client(tcp::socket tcp_socket, const std::string &chosen_pqc_alg, const std::string &qkd_ip)
{   
    std::vector<unsigned char> aes_keys;
    try {
        std::cout << "New client connected: " << tcp_socket.remote_endpoint().address() << "\n";

        // --- 1. Send READY to client ---
        const std::string ready_msg = "READY";
        boost::asio::write(tcp_socket, boost::asio::buffer(ready_msg));
        std::cout << "READY sent to client\n";

        // --- 2. Wait for client-initiated rekey trigger ---
        char init_buf[64] = {0};
        boost::system::error_code ec;
        size_t init_len = tcp_socket.read_some(boost::asio::buffer(init_buf), ec);
        if (!ec && init_len > 0) {
            std::string init_msg(init_buf, init_len);
            if (init_msg == "INIT_REKEY") {
                // --- 3. Perform initial rekey ---
                aes_keys = rekey_srv(tcp_socket, qkd_ip, chosen_pqc_alg);
                std::cout << "Initial rekey done, keys established\n";
            }
        }

        // --- Check if keys were established ---
        if (aes_keys.size() < AES_GCM_KEY_LEN * 2) {
            std::cerr << "Key establishment failed or keys are too short. Closing connection.\n";
            tcp_socket.close();
            return;
        }

        // --- 4. Open UDP socket and handshake ---
        boost::asio::io_context io_context;
        udp::socket udp_socket(io_context, udp::endpoint(udp::v4(), PORT));
        std::cout << "Server UDP ready on port " << PORT << "\n";

        char udp_buf[1024];
        udp::endpoint client_udp_ep;
        size_t len = udp_socket.receive_from(boost::asio::buffer(udp_buf), client_udp_ep);
        std::cout << "Server received UDP: " << std::string(udp_buf, len) << "\n";

        std::string reply = "Hello from server UDP";
        udp_socket.send_to(boost::asio::buffer(reply), client_udp_ep);
        std::cout << "Server replied to UDP\n";

        // Set sockets to non-blocking for the main loop
        udp_socket.non_blocking(true);
        tcp_socket.non_blocking(true);

        // --- 5. Main loop: handle further TCP commands ---
        std::atomic<int> read_order(1), send_order(1);
        int tundesc = tun_open();
        // Server's decryption key must match client's encryption key.
        // Server's encryption key must match client's decryption key.
        // So we swap the assignment compared to the client.
        std::vector<unsigned char> key_decrypt(aes_keys.begin(), aes_keys.begin() + AES_GCM_KEY_LEN);
        std::vector<unsigned char> key_encrypt(aes_keys.begin() + AES_GCM_KEY_LEN, aes_keys.end());

        int threads_max = std::thread::hardware_concurrency() > 1 ? std::thread::hardware_concurrency() - 1 : 1;
        std::atomic<int> threads_available = threads_max;

        while (true) {
            // Check for TCP commands
            char cmd_buf[1024] = {0};
            size_t cmd_len = tcp_socket.read_some(boost::asio::buffer(cmd_buf), ec);
            if (!ec && cmd_len > 0) {
                std::string cmd(cmd_buf, cmd_len);
                if (cmd == "REKEY_CLIENT_INITIATED") {
                    std::cout << "Client requested rekey\n";
                    aes_keys = rekey_srv(tcp_socket, qkd_ip, chosen_pqc_alg);
                    key_decrypt.assign(aes_keys.begin(), aes_keys.begin() + AES_GCM_KEY_LEN);
                    key_encrypt.assign(aes_keys.begin() + AES_GCM_KEY_LEN, aes_keys.end());
                } else if (cmd == "exit") {
                    std::cout << "Client requested exit\n";
                    break;
                }
            } else if (ec != boost::asio::error::would_block) {
                std::cerr << "TCP connection error or closed: " << ec.message() << "\n";
                break;
            }

            // Process UDP and TUN traffic
            if (E_N_C_R(udp_socket, client_udp_ep, key_encrypt, tundesc, read_order, send_order) ||
                D_E_C_R(udp_socket, client_udp_ep, key_decrypt, tundesc, read_order, send_order)) {
                if (threads_available > 0) {
                    threads_available -= 1;
                    std::thread(thread_encrypt, &udp_socket, client_udp_ep, &key_encrypt, &key_decrypt,
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
                select(max_fd + 1, &fds, NULL, NULL, &tv); // Wait for activity
            }
        }

        close(tundesc);
        tcp_socket.close();
        udp_socket.close();
    }
    catch (const std::exception &e) {
        std::cerr << "Server exception: " << e.what() << "\n";
    }
}


int main(int argc, char* argv[])
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
    

    // --- Initialize OpenSSL ---
    if (!OPENSSL_init_crypto(0, nullptr)) return 1;
    OSSL_PROVIDER *defprov = OSSL_PROVIDER_load(nullptr, "default");

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

    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), KEYPORT));
        std::cout << "Server listening on port " << KEYPORT << std::endl;

        while (true) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);
            if(!qkd_ip.empty()){
                std::thread(handle_client, std::move(socket), chosen_pqc_alg, qkd_ip).detach();
            }
            else{
                std::thread(handle_client, std::move(socket), chosen_pqc_alg, "").detach();
            }
        }
    } catch (const std::exception &e) {
        std::cerr << "Server exception: " << e.what() << std::endl;
        return 1;
    }

    if (defprov) OSSL_PROVIDER_unload(defprov);
    return 0;
}
