#ifndef SERVER_H
#define SERVER_H

#include <string>
#include <map>
#include "client.h"

class User{
    public:
        std::string username;
        std::string password;
        std::string privateKey;
        std::string publicKey;
        std::string certificate;
        std::string timestamp;
};

extern std::map<std::string, User> userDatabase;
extern std::map<std::string, std::string> revokedCertificates;

class Server {
public:
    static bool registerUser(const std::string& username, const std::string& password);
    static bool authenticateUser(const std::string& username, const std::string& password);
    static bool generateCertificate(const std::string& username);
    static bool revokeCertificate(const std::string& username);
    static bool verifyCertificate(const std::string& username);
    static void listCertificates();
    static void showUserInfo();

private:
    static bool createKeyPair(const std::string& username, std::string& privateKey, std::string& publicKey);
    static bool createCertificate(const std::string& username, const std::string& publicKey, std::string& certificate);
};

#endif // SERVER_H
