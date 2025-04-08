#ifndef SERVER_H
#define SERVER_H

#include <iostream>
#include <string>
#include <string.h>
#include <sstream>
#include <fstream>
#include <filesystem>
#include <unordered_map>
#include "clientInfo.h"
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509_vfy.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

using namespace std;

class Server {
private:
    unordered_map<string, ClientInfo> clients; // Stores username-certificate
    int server_socket;

public:
    Server();
    ~Server();

    void start(int port);
    void handleClient(int client_socket);
    bool sendMessageToClient(int client_socket, const string &message);
    
    void storeUserCredentials(const string& username, const string& password);
    void registerUser(const string& username, const string& password);
    bool authenticateUser(const string& username, const string& password);
    string signCSR(const string& username, const string& csrContent);

    pair<string,string> generateCA(const string& keyFile, const string& certFile);
    string generateCRL(const string& crlFile, const string& caKeyFile, const string& caCertFile, const string& certFile);
    bool revokeCertificate(const string& certFile, const string& crlFile, const string& caKeyFile, const string& caCertFile); 
};

#endif
