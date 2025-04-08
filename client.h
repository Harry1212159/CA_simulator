#ifndef CLIENT_H
#define CLIENT_H

#include <string>
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>
#include <vector>
#include <fstream>
#include <openssl/x509.h>
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/bio.h>
#include <openssl/x509_vfy.h>

using namespace std;
// Functions that implement client operations
void clientRegister();
void clientLogin();
void clientRequestCertificate();
void clientRevokeCertificate();
void clientMenu();

#endif // CLIENT_H