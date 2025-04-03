#include "server.h"
#include <iostream>
#include <fstream>
#include <ctime>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>

std::map<std::string, User> userDatabase;
std::map<std::string, std::string> revokedCertificates;

std::string getCurrentTime() {
    time_t now = time(0);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", localtime(&now));
    return std::string(buffer);
}

bool Server::registerUser(const std::string& username, const std::string& password) {
    if (userDatabase.find(username) != userDatabase.end()) {
        return false;
    }
    User newUser = {username, password, "", "", "", ""};
    userDatabase[username] = newUser;
    return true;
}

bool Server::authenticateUser(const std::string& username, const std::string& password) {
    auto it = userDatabase.find(username);
    return (it != userDatabase.end() && it->second.password == password);
}

bool Server::createKeyPair(const std::string& username, std::string& privateKey, std::string& publicKey) {
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    if (!ctx) {
        std::cerr << "EVP_PKEY_CTX_new_id failed\n";
        return false;
    }

    if (EVP_PKEY_keygen_init(ctx) <= 0 || EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "EVP_PKEY_keygen_init failed\n";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pkey = NULL;
    if (EVP_PKEY_generate(ctx, &pkey) <= 0) {
        std::cerr << "EVP_PKEY_generate failed\n";
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx);

    // Lưu khóa riêng tư
    BIO* privBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(privBIO, pkey, NULL, NULL, 0, NULL, NULL);
    char* privData;
    long privLen = BIO_get_mem_data(privBIO, &privData);
    privateKey.assign(privData, privLen);
    BIO_free(privBIO);

    // Lưu khóa công khai
    BIO* pubBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_PUBKEY(pubBIO, pkey);
    char* pubData;
    long pubLen = BIO_get_mem_data(pubBIO, &pubData);
    publicKey.assign(pubData, pubLen);
    BIO_free(pubBIO);

    EVP_PKEY_free(pkey);
    return true;
}

bool Server::createCertificate(const std::string& username, const std::string& publicKey, std::string& certificate) {
    X509* x509 = X509_new();
    if (!x509) return false;

    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L);  // Hiệu lực 1 năm

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)username.c_str(), -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Load khóa công khai
    EVP_PKEY* pkey = EVP_PKEY_new();
    BIO* bio = BIO_new_mem_buf(publicKey.data(), publicKey.size());
    PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL);
    BIO_free(bio);
    X509_set_pubkey(x509, pkey);
    EVP_PKEY_free(pkey);

    // Tạo khóa CA để ký chứng chỉ
    EVP_PKEY* caPkey = EVP_PKEY_new();
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, NULL);
    EVP_PKEY_keygen_init(ctx);
    EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048);
    EVP_PKEY_generate(ctx, &caPkey);
    EVP_PKEY_CTX_free(ctx);

    X509_sign(x509, caPkey, EVP_sha256());
    EVP_PKEY_free(caPkey);

    // Lưu chứng chỉ
    BIO* certBIO = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBIO, x509);
    char* certData;
    long certLen = BIO_get_mem_data(certBIO, &certData);
    certificate.assign(certData, certLen);
    BIO_free(certBIO);
    X509_free(x509);

    return true;
}

bool Server::generateCertificate(const std::string& username) {
    auto it = userDatabase.find(username);
    if (it == userDatabase.end()) {
        return false;
    }

    std::string privateKey, publicKey, certificate;
    if (!createKeyPair(username, privateKey, publicKey) || !createCertificate(username, publicKey, certificate)) {
        return false;
    }

    it->second.privateKey = privateKey;
    it->second.publicKey = publicKey;
    it->second.certificate = certificate;
    it->second.timestamp = getCurrentTime();

    return true;
}

bool Server::revokeCertificate(const std::string& username) {
    auto it = userDatabase.find(username);
    if (it != userDatabase.end() && !it->second.certificate.empty()) {
        revokedCertificates[username] = it->second.certificate;
        it->second.certificate.clear();
        return true;
    }
    return false;
}

bool Server::verifyCertificate(const std::string& username) {
    return userDatabase.find(username) != userDatabase.end() &&
           !userDatabase[username].certificate.empty() &&
           revokedCertificates.find(username) == revokedCertificates.end();
}

void Server::listCertificates() {
    std::cout << "Issued Certificates:\n";
    for (const auto& entry : userDatabase) {
        if (!entry.second.certificate.empty()) {
            std::cout << "User: " << entry.second.username << " - Issued at: " << entry.second.timestamp << "\n";
        }
    }
}

void Server::showUserInfo() {
    if (userDatabase.empty()) {
        std::cout << "No users in the database.\n";
        return;
    }

    std::cout << "User Information:\n";
    for (const auto& entry : userDatabase) {
        const User& user = entry.second;
        std::cout << "Username: " << user.username << "\n";
        std::cout << "Private Key:\n" << user.privateKey << "\n";
        std::cout << "Public Key:\n" << user.publicKey << "\n";
        std::cout << "Certificate:\n" << user.certificate << "\n";
        std::cout << "-----------------------------\n";
    }
}
