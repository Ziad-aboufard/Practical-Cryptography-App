#include <iostream>
#include <string>
#include <vector>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/aes.h>
#include <thread>

// AES key and IV (use securely generated keys in production)
const std::string aes_key = "01234567890123456789012345678901"; // 32-byte AES key
const std::string aes_iv = "0123456789012345";                  // 16-byte IV for AES
const std::string hmac_key = "hmac_secure_key";                 // HMAC key

// AES encryption function
std::string aes_encrypt(const std::string &message, const std::string &key, const std::string &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> ciphertext(message.size() + AES_BLOCK_SIZE);
    int len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key.data(), (unsigned char *)iv.data());
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, (unsigned char *)message.data(), message.size());
    int ciphertext_len = len;
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(ciphertext.begin(), ciphertext.begin() + ciphertext_len);
}

// HMAC computation function
std::string compute_hmac(const std::string &message, const std::string &key)
{
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key.data(), key.size(), (unsigned char *)message.data(), message.size(), hmac, &hmac_len);
    return std::string((char *)hmac, hmac_len);
}

// Function to receive messages
void receive_messages(SSL *ssl)
{
    char buffer[1024];
    while (true)
    {
        int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0)
        {
            std::cerr << "Disconnected from server or error occurred\n";
            break;
        }
        buffer[bytes_received] = '\0';
        std::cout << "\n[Message]: " << buffer << std::endl;
    }
}

int main()
{
    std::cout << "Initializing OpenSSL..." << std::endl;
    SSL_library_init();
    OpenSSL_add_ssl_algorithms();
    SSL_load_error_strings();

    std::cout << "Connecting to server..." << std::endl;
    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        std::cerr << "Failed to create socket" << std::endl;
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(5678);
    server_addr.sin_addr.s_addr = inet_addr("127.0.0.1");

    if (connect(server_socket, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0)
    {
        std::cerr << "Failed to connect to server" << std::endl;
        close(server_socket);
        return 1;
    }
    std::cout << "Connected to server" << std::endl;

    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        close(server_socket);
        return 1;
    }

    SSL *ssl = SSL_new(ctx);
    SSL_set_fd(ssl, server_socket);

    if (SSL_connect(ssl) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_free(ssl);
        SSL_CTX_free(ctx);
        close(server_socket);
        return 1;
    }
    std::cout << "SSL handshake successful" << std::endl;

    // Authenticate user
    std::string username, password;
    std::cout << "Enter username: ";
    std::getline(std::cin, username);
    SSL_write(ssl, username.c_str(), username.size());

    std::cout << "Enter password: ";
    std::getline(std::cin, password);
    SSL_write(ssl, password.c_str(), password.size());

    char buffer[512];
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received > 0)
    {
        buffer[bytes_received] = '\0';
        std::cout << "Server: " << buffer << std::endl;
    }
    else
    {
        std::cerr << "Failed to receive response from server" << std::endl;
    }

    // Start a thread for receiving messages
    std::thread receiver_thread(receive_messages, ssl);

    // Messaging loop
    std::cout << "You can now send messages to other clients." << std::endl;
    while (true)
    {
        std::string recipient, message;

        std::cout << "Enter recipient username (or 'exit' to quit): ";
        std::getline(std::cin, recipient);
        if (recipient == "exit")
        {
            std::cout << "Exiting client..." << std::endl;
            break;
        }

        std::cout << "Enter your message: ";
        std::getline(std::cin, message);

        // Encrypt the message and compute HMAC
        std::string encrypted_message = aes_encrypt(message, aes_key, aes_iv);
        std::string message_hmac = compute_hmac(encrypted_message, hmac_key);

        // Format message as "recipient:encrypted_message:hmac"
        std::string full_message = recipient + ":" + encrypted_message + ":" + message_hmac;

        // Send message to server
        SSL_write(ssl, full_message.c_str(), full_message.size());
        std::cout << "Message sent to server." << std::endl;
    }

    // Wait for the receiving thread to finish
    receiver_thread.join();

    SSL_free(ssl);
    SSL_CTX_free(ctx);
    close(server_socket);
    return 0;
}
