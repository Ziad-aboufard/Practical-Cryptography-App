#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <thread>
#include <mutex>
#include <map>

// Credentials file
const char *credentials_file_path = "/home/kali/Desktop/Crypto M2/credentials.txt";
const std::string aes_key = "01234567890123456789012345678901"; // 32-byte AES key
const std::string aes_iv = "0123456789012345";                  // 16-byte IV for AES
const std::string hmac_key = "hmac_secure_key";                 // Key for HMAC

std::map<std::string, SSL *> client_map;
std::mutex client_map_mutex;

// AES decryption function
std::string aes_decrypt(const std::string &ciphertext, const std::string &key, const std::string &iv)
{
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<unsigned char> plaintext(ciphertext.size());
    int len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), nullptr, (unsigned char *)key.data(), (unsigned char *)iv.data());
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, (unsigned char *)ciphertext.data(), ciphertext.size());
    int plaintext_len = len;
    EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return std::string(plaintext.begin(), plaintext.begin() + plaintext_len);
}

// HMAC verification function
bool verify_hmac(const std::string &message, const std::string &received_hmac, const std::string &key)
{
    unsigned char hmac[EVP_MAX_MD_SIZE];
    unsigned int hmac_len;
    HMAC(EVP_sha256(), key.data(), key.size(), (unsigned char *)message.data(), message.size(), hmac, &hmac_len);
    std::string computed_hmac((char *)hmac, hmac_len);
    return computed_hmac == received_hmac;
}

// Handle client communication
void handle_client(SSL *ssl)
{
    char buffer[1024];
    std::string username;

    // Receive username
    int bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0)
    {
        std::cerr << "Error receiving username\n";
        SSL_free(ssl);
        return;
    }
    buffer[bytes_received] = '\0';
    username = buffer;

    // Receive password
    bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
    if (bytes_received <= 0)
    {
        std::cerr << "Error receiving password\n";
        SSL_free(ssl);
        return;
    }
    buffer[bytes_received] = '\0';
    std::string password = buffer;

    // Authenticate
    std::ifstream file(credentials_file_path);
    std::string stored_username, stored_password;
    bool authenticated = false;
    while (file >> stored_username >> stored_password)
    {
        if (username == stored_username && password == stored_password)
        {
            authenticated = true;
            break;
        }
    }

    if (!authenticated)
    {
        std::string auth_fail = "Authentication failed";
        SSL_write(ssl, auth_fail.c_str(), auth_fail.size());
        SSL_free(ssl);
        return;
    }

    std::string auth_success = "Authentication successful";
    SSL_write(ssl, auth_success.c_str(), auth_success.size());
    std::cout << "Authenticated user: " << username << std::endl;

    {
        std::lock_guard<std::mutex> lock(client_map_mutex);
        client_map[username] = ssl;
    }

    // Messaging loop
    while (true)
    {
        bytes_received = SSL_read(ssl, buffer, sizeof(buffer) - 1);
        if (bytes_received <= 0)
        {
            std::cerr << "Client disconnected or error occurred\n";
            break;
        }
        buffer[bytes_received] = '\0';
        std::string received_message(buffer);

        size_t first_colon = received_message.find(':');
        size_t second_colon = received_message.find(':', first_colon + 1);

        if (first_colon == std::string::npos || second_colon == std::string::npos)
        {
            std::cerr << "Invalid message format\n";
            continue;
        }

        std::string recipient = received_message.substr(0, first_colon);
        std::string encrypted_message = received_message.substr(first_colon + 1, second_colon - first_colon - 1);
        std::string received_hmac = received_message.substr(second_colon + 1);

        if (!verify_hmac(encrypted_message, received_hmac, hmac_key))
        {
            std::cerr << "HMAC verification failed\n";
            continue;
        }

        std::string decrypted_message = aes_decrypt(encrypted_message, aes_key, aes_iv);
        std::cout << "Decrypted message from " << username << ": " << decrypted_message << std::endl;

        // Forward message to recipient
        {
            std::lock_guard<std::mutex> lock(client_map_mutex);
            auto it = client_map.find(recipient);
            if (it != client_map.end())
            {
                SSL *recipient_ssl = it->second;
                std::string forward_message = "From " + username + ": " + decrypted_message;
                SSL_write(recipient_ssl, forward_message.c_str(), forward_message.size());
            }
            else
            {
                std::cerr << "Recipient not found: " << recipient << std::endl;
                std::string error_message = "Error: Recipient " + recipient + " not found.";
                SSL_write(ssl, error_message.c_str(), error_message.size());
            }
        }
    }

    {
        std::lock_guard<std::mutex> lock(client_map_mutex);
        client_map.erase(username);
    }
    SSL_free(ssl);
}

int main()
{
    SSL_library_init();
    OpenSSL_add_all_algorithms();
    SSL_load_error_strings();

    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
    {
        ERR_print_errors_fp(stderr);
        return 1;
    }

    const char *cert_path = "/home/kali/Desktop/Crypto M2/server.crt";
    const char *key_path = "/home/kali/Desktop/Crypto M2/server.key";

    if (SSL_CTX_use_certificate_file(ctx, cert_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (SSL_CTX_use_PrivateKey_file(ctx, key_path, SSL_FILETYPE_PEM) <= 0)
    {
        ERR_print_errors_fp(stderr);
        SSL_CTX_free(ctx);
        return 1;
    }

    int server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket < 0)
    {
        std::cerr << "Failed to create socket\n";
        SSL_CTX_free(ctx);
        return 1;
    }

    sockaddr_in server_addr{};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(5678);

    if (bind(server_socket, reinterpret_cast<sockaddr *>(&server_addr), sizeof(server_addr)) < 0)
    {
        std::cerr << "Bind failed\n";
        close(server_socket);
        SSL_CTX_free(ctx);
        return 1;
    }

    if (listen(server_socket, 5) < 0)
    {
        std::cerr << "Listen failed\n";
        close(server_socket);
        SSL_CTX_free(ctx);
        return 1;
    }

    std::cout << "Server listening on port 5678" << std::endl;

    while (true)
    {
        sockaddr_in client_addr{};
        socklen_t client_size = sizeof(client_addr);
        int client_socket = accept(server_socket, reinterpret_cast<sockaddr *>(&client_addr), &client_size);
        if (client_socket < 0)
        {
            std::cerr << "Accept failed\n";
            continue;
        }

        SSL *ssl = SSL_new(ctx);
        SSL_set_fd(ssl, client_socket);

        if (SSL_accept(ssl) <= 0)
        {
            ERR_print_errors_fp(stderr);
            SSL_free(ssl);
            close(client_socket);
            continue;
        }

        std::cout << "Client connected: " << inet_ntoa(client_addr.sin_addr) << std::endl;
        std::thread(handle_client, ssl).detach();
    }

    close(server_socket);
    SSL_CTX_free(ctx);
    return 0;
}
