#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <arpa/inet.h>
#include <sched.h>
#include <sys/wait.h>
#include <netinet/in.h>
#include <sys/un.h>
#include <csignal>
#include <string.h>
#include <bits/stdc++.h>
#include <sys/poll.h>
#include <sys/un.h>
#include <string>
#include <sstream>
#include <iostream>
#include <openssl/sha.h>
#include <curl/curl.h>
#include <cstdlib>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#define BUFSIZE 6000
using namespace std;

int Create_TCPSocket_server()
{
    int sfd;
    sfd = socket(AF_INET, SOCK_STREAM, 0);
    int opt = 1;
    setsockopt(sfd, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = inet_addr("127.0.0.1");
    addr.sin_port = htons(9000);
    bind(sfd, (struct sockaddr *)&addr, sizeof(addr));
    listen(sfd, 3);
    return sfd;
}

int Create_TCPSocket_client(int port, string ip)
{
    int sfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sfd == -1)
    {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in address;
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = inet_addr(ip.c_str());
    if (connect(sfd, (struct sockaddr *)&address, sizeof(address)) == -1)
    {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }
    return sfd;
}

string hashSHA256(string &input)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char *>(input.c_str()), input.length(), hash);
    string hashedString;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; ++i)
    {
        char buf[3];
        sprintf(buf, "%02x", hash[i]); //coverts each byte of the hash to 2-digit hexa decimal
        hashedString += buf;
    }
    return hashedString;
}

// Callback function to write received data
size_t WriteCallback(void *ptr, size_t size, size_t nmemb, string *data)
{
    data->append((char *)ptr, size * nmemb);
    return size * nmemb;
}

string mailSender(string email, string otp)
{
    CURL *curl;
    CURLcode res;
    string response;
    string params = "email=" + email + "&otp=" + otp;

    // Initialize cURL
    curl = curl_easy_init();
    if (curl)
    {
        // Set the URL
        curl_easy_setopt(curl, CURLOPT_URL, "http://localhost:9090");

        // Set the request type to POST
        curl_easy_setopt(curl, CURLOPT_POST, 1L);

        // Set the post fields
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, params.c_str());

        // Set the write callback function
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);

        // Set the pointer to response string
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response);

        // Perform the request
        res = curl_easy_perform(curl);

        // Check for errors
        if (res != CURLE_OK)
            cerr << "curl_easy_perform() failed: " << curl_easy_strerror(res) << endl;

        // Cleanup
        curl_easy_cleanup(curl);

        return response;
    }
    return "error";
}

RSA *generateRSAKeyPair(int bits)
{
    RSA *rsa = RSA_new();
    BIGNUM *e = BN_new();

    // Set public exponent
    BN_set_word(e, RSA_F4);

    // Generate key pair
    RSA_generate_key_ex(rsa, bits, e, NULL);

    BN_free(e);

    return rsa;
}

char *printHex(const BIGNUM *bn, const char *label)
{
    char *hex = BN_bn2hex(bn);
    return hex;
}

RSA *setRSAAttributes(const char *pubN, const char *pubE)
{
    RSA *rsa = RSA_new();
    BIGNUM *n = NULL, *e = NULL;

    BN_hex2bn(&n, pubN);
    BN_hex2bn(&e, pubE);

    RSA_set0_key(rsa, n, e, NULL);
    return rsa;
}
string rsaPrivateEncrypt(const unsigned char *plaintext, int plaintextLen, RSA *rsa)
{
    unsigned char *encrypted = new unsigned char[RSA_size(rsa)]; 
    int encryptedLen = RSA_private_encrypt(plaintextLen, plaintext, encrypted, rsa, RSA_PKCS1_PADDING);
    if (encryptedLen == -1)
    {
       
        delete[] encrypted; 
        return "";          
    }
    string EncryptedText(reinterpret_cast<const char *>(encrypted), encryptedLen);
    delete[] encrypted; 
    return EncryptedText;
}

string rsaPublicDecrypt(const unsigned char *encrypted, int encryptedLen, RSA *rsa)
{
    unsigned char *decrypted = new unsigned char[RSA_size(rsa)]; 
    int decryptedLen = RSA_public_decrypt(encryptedLen, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decryptedLen == -1)
    {
        delete[] decrypted; 
        return "";          
    }
    string DecryptedText(reinterpret_cast<const char *>(decrypted), decryptedLen);
    delete[] decrypted; 
    return DecryptedText;
}

string rsaPublicEncrypt(const unsigned char *plaintext, int plaintextLen, RSA *rsa)
{
    unsigned char *encrypted = new unsigned char[RSA_size(rsa)]; 
    int encryptedLen = RSA_public_encrypt(plaintextLen, plaintext, encrypted, rsa, RSA_PKCS1_PADDING);
    if (encryptedLen == -1)
    {
        
        delete[] encrypted; 
        return "";          
    }
    string EncryptedText(reinterpret_cast<const char *>(encrypted), encryptedLen);
    delete[] encrypted; 
    return EncryptedText;
}

string rsaPrivateDecrypt(const unsigned char *encrypted, int encryptedLen, RSA *rsa)
{
    unsigned char *decrypted = new unsigned char[RSA_size(rsa)]; 
    int decryptedLen = RSA_private_decrypt(encryptedLen, encrypted, decrypted, rsa, RSA_PKCS1_PADDING);
    if (decryptedLen == -1)
    {
        
        delete[] decrypted; 
        return "";        
    }
    string DecryptedText(reinterpret_cast<const char *>(decrypted), decryptedLen);
    delete[] decrypted; 
    return DecryptedText;
}