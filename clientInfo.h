#ifndef CLIENTINFO_H
#define CLIENTINFO_H

#include <string>

class ClientInfo {
public:
    std::string username;
    std::string password;
    std::string certificate; // The X.509 certificate

    // You can add more fields as needed, e.g. public key, registration date, etc.

    ClientInfo() = default;
    ClientInfo(const std::string& uname, const std::string& pwd, const std::string& cert = "")
        : username(uname), password(pwd), certificate(cert) {}
};

#endif // CLIENTINFO_H
