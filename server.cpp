#define PORT 8080
#include "server.h"

Server::Server() {
    // Create a socket
    server_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (server_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }
}

Server::~Server() {
    close(server_socket);
}

void Server::start(int port) {
    struct sockaddr_in server_addr, client_addr;
    socklen_t client_size = sizeof(client_addr);

    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(port);

    if (bind(server_socket, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        exit(EXIT_FAILURE);
    }

    if (listen(server_socket, 5) < 0) {
        perror("Listen failed");
        exit(EXIT_FAILURE);
    }

    cout << "Server running on port " << port << "...\n";

    while (true) {
        int client_socket = accept(server_socket, (struct sockaddr*)&client_addr, &client_size);
        if (client_socket < 0) {
            perror("Client accept failed");
            continue;
        }

        cout << "Client connected.\n";
        handleClient(client_socket);
        close(client_socket);
    }
}

bool Server::sendMessageToClient(int client_socket, const string &message) {
    ssize_t totalSent = 0;
    ssize_t messageSize = message.size();
    const char* data = message.c_str();

    while (totalSent < messageSize) {
        ssize_t sent = send(client_socket, data + totalSent, messageSize - totalSent, 0);
        if (sent <= 0) {
            perror("Send failed");
            return false;
        }
        totalSent += sent;
    }
    return true;
}

void Server::storeUserCredentials(const string& username, const string& password) {
    // Ensure the "users" directory exists
    filesystem::create_directories("users");
    cout << "Current working directory: " << filesystem::current_path() << endl;

    // Create the filename for the user's credentials
    string filename = "users/" + username + ".txt";

    // Open the file for writing
    ofstream ofs(filename);
    if (!ofs.is_open()) {
        cerr << "Failed to open " << filename << " for writing." << endl;
        return;
    }
    
    // Write the username and password (each on a separate line)
    ofs << username << "\n" << password << "\n";
    ofs.close();
    cout << "Stored credentials for user '" << username << "'." << endl;
}


// Registration: creates a file for the new user if it doesn't already exist
void Server::registerUser(const string &username, const string &password) {
    string filename = "users/" + username + ".txt";
    if (filesystem::exists(filename)) {
        cout << "Registration failed: User '" << username << "' already exists." << endl;
        return;
    }
    storeUserCredentials(username, password);
    cout << "Registration successful for user '" << username << "'." << endl;
}

// Authentication: reads the file for the given username and checks the stored password
bool Server::authenticateUser(const string &username, const string &password) {
    string filename = "users/" + username + ".txt";
    if (!filesystem::exists(filename)) {
        // No such user file exists
        return false;
    }
    
    ifstream ifs(filename);
    if (!ifs) {
        cerr << "Failed to open " << filename << " for reading." << endl;
        return false;
    }
    
    // Read stored username and password (assuming the first line is the username, second line is the password)
    string storedUsername, storedPassword;
    getline(ifs, storedUsername);
    getline(ifs, storedPassword);
    ifs.close();
    
    // Check credentials (note: in production, passwords should be hashed!)
    return (storedUsername == username && storedPassword == password);
}

void Server::handleClient(int client_socket) {
    char buffer[1024] = {0};
    int bytesRead;
    
    // Loop continuously to receive multiple commands from the same client.
    while ((bytesRead = read(client_socket, buffer, sizeof(buffer) - 1)) > 0) {
        buffer[bytesRead] = '\0';
        string request(buffer);
        cout << "Received request: " << request << endl;
        
        // Parse the incoming request
        istringstream iss(request);
        string command, username, password;
        iss >> command >> username;
        
        string response;
        
        if (command == "REGISTER") {
            iss >> password;
            string filename = "users/" + username + ".txt";
            bool existedBefore = filesystem::exists(filename);
            registerUser(username, password);
            if (filesystem::exists(filename) && !existedBefore) {
                response = "Registration successful!";
            } else {
                response = "Registration failed: User already exists!";
            }
            sendMessageToClient(client_socket, response);
        } else if (command == "LOGIN") {
            iss >> password;
            if (authenticateUser(username, password)) {
                response = "Login successful!";
            } else {
                response = "Invalid credentials!";
            }
            sendMessageToClient(client_socket, response);
        } else if (command == "CERT") {
            // Extract the CSR content from the request
            string csrContent = request.substr(request.find('\n') + 1);
            cout << "Received CSR content for user: " << username << endl;

            // Sign the CSR
            string signedCert = signCSR(username, csrContent);
            if (!signedCert.empty()) {
                response = "CERTIFICATE\n" + signedCert;
            } else {
                response = "Certificate generation failed.";
            }

            // Send the signed certificate back to the client
            send(client_socket, response.c_str(), response.size(), 0);
        } 
        else if (command == "REVOKE") {
            // Revoke the certificate for the user
            string certFile = username + "_signed_certificate.pem";
            string caKeyFile = "ca_private.key";
            string caCertFile = "ca_certificate.pem";
            generateCA(caKeyFile, caCertFile);
            
            // Generate the CRL
            string crlFile = "crl.pem";
            generateCRL(crlFile, caKeyFile, caCertFile, certFile);
            
            if (revokeCertificate(certFile, crlFile, caKeyFile, caCertFile)) {
                response = "Certificate revoked successfully.";
            } else {
                response = "Failed to revoke certificate.";
            }
            sendMessageToClient(client_socket, response);
        }
        else if (command == "EXIT") {
            cout << "Client requested exit." << endl;
            response = "Goodbye!";
            sendMessageToClient(client_socket, response);
            break;
        } else {
            response = "Unknown command!";
            sendMessageToClient(client_socket, response);
        }
        
        memset(buffer, 0, sizeof(buffer)); // Clear buffer before next read
    }
}

string Server::signCSR(const string& username, const string& csrContent) {
    BIO* csrBIO = BIO_new_mem_buf(csrContent.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(csrBIO, NULL, NULL, NULL);
    if (!req) {
        cerr << "Failed to parse CSR\n";
        BIO_free(csrBIO);
        return "";
    }

    string keyFilePath = "./" + username + "_private.key";
    string certFilePath = "./" + username + "_certificate.pem";
    
    FILE* keyFile = fopen(keyFilePath.c_str(), "r");
    FILE* certFile = fopen(certFilePath.c_str(), "r");

    if (!keyFile || !certFile) {
        cerr << "Failed to open CA key or certificate for user: " << username << "\n";
        if (keyFile) fclose(keyFile);
        if (certFile) fclose(certFile);
        BIO_free(csrBIO);
        return "";
    }

    EVP_PKEY* caKey = PEM_read_PrivateKey(keyFile, NULL, NULL, NULL);
    X509_REQ* caCert = PEM_read_X509_REQ(certFile, NULL, NULL, NULL);
    // X509* caCert = PEM_read_X509(certFile, NULL, NULL, NULL);
    fclose(keyFile);
    fclose(certFile);

    if (!caKey || !caCert) {
        cerr << "Failed to load CA key or certificate for user: " << username << "\n";
        if (caKey) EVP_PKEY_free(caKey);
        if (caCert) X509_REQ_free(caCert);
        BIO_free(csrBIO);
        return "";
    }

    // Create a new certificate
    X509* newCert = X509_new();
    if (!newCert) {
        cerr << "Failed to create new X509 certificate.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        BIO_free(csrBIO);
        return "";
    }

    ASN1_INTEGER_set(X509_get_serialNumber(newCert), 1); // Set serial number
    X509_gmtime_adj(X509_getm_notBefore(newCert), 0);    // Set validity start time
    X509_gmtime_adj(X509_getm_notAfter(newCert), 31536000L); // Set validity for 1 year

    // Set issuer name from CA certificate
    if (!X509_set_issuer_name(newCert, X509_REQ_get_subject_name(caCert))) {
        cerr << "Failed to set issuer name.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        BIO_free(csrBIO);
        return "";
    }

    // Set subject from CSR
    if (!X509_set_subject_name(newCert, X509_REQ_get_subject_name(req))) {
        cerr << "Failed to set subject name from CSR.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        X509_REQ_free(req);
        BIO_free(csrBIO);
        return "";
    }

    EVP_PKEY* reqPubKey = X509_REQ_get_pubkey(req);
    if (!reqPubKey || !X509_set_pubkey(newCert, reqPubKey)) {
        cerr << "Failed to set public key from CSR.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        X509_REQ_free(req);
        BIO_free(csrBIO);
        return "";
    }

    // Sign the certificate
    if (!X509_sign(newCert, caKey, EVP_sha256())) {
        cerr << "Signing failed for user: " << username << "\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        X509_REQ_free(req);
        BIO_free(csrBIO);
        return "";
    }

    // Output the signed certificate to a string
    BIO* out = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(out, newCert);
    char* certData;
    long len = BIO_get_mem_data(out, &certData);
    string signedCert(certData, len);

    // Clean up
    EVP_PKEY_free(caKey);
    X509_REQ_free(caCert);
    X509_free(newCert);
    X509_REQ_free(req);
    BIO_free(out);
    BIO_free(csrBIO);

    return signedCert;
}

pair<string,string> Server::generateCA(const std::string& keyFile, const std::string& certFile) {
    EVP_PKEY* caKey = nullptr;
    // Create a context for RSA key generation using the EVP API.
    EVP_PKEY_CTX* pctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!pctx) {
        std::cerr << "Failed to create EVP_PKEY_CTX" << std::endl;
        return std::make_pair("", "");
    }
    if (EVP_PKEY_keygen_init(pctx) <= 0 ||
        EVP_PKEY_CTX_set_rsa_keygen_bits(pctx, 2048) <= 0) {
        std::cerr << "Failed to initialize RSA key generation" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return std::make_pair("", "");
    }
    if (EVP_PKEY_generate(pctx, &caKey) <= 0) {
        std::cerr << "Failed to generate RSA key" << std::endl;
        EVP_PKEY_CTX_free(pctx);
        return std::make_pair("", "");
    }
    EVP_PKEY_CTX_free(pctx);

    // Create a new self-signed X509 certificate.
    X509* caCert = X509_new();
    if (!caCert) {
        std::cerr << "Failed to create X509 structure" << std::endl;
        EVP_PKEY_free(caKey);
        return std::make_pair("", "");
    }
    
    // Set serial number and validity period.
    ASN1_INTEGER_set(X509_get_serialNumber(caCert), 1);
    X509_gmtime_adj(X509_getm_notBefore(caCert), 0);
    X509_gmtime_adj(X509_getm_notAfter(caCert), 10 * 365 * 24 * 3600L); // valid for 10 years

    // Set the certificate’s public key.
    X509_set_pubkey(caCert, caKey);

    // Build subject name
    X509_NAME* name = X509_get_subject_name(caCert);
    X509_NAME_add_entry_by_txt(name, "C",  MBSTRING_ASC, (const unsigned char*)"US", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O",  MBSTRING_ASC, (const unsigned char*)"My Test CA", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)"Test CA", -1, -1, 0);

    // Since it's self-signed, issuer is the same as subject.
    X509_set_issuer_name(caCert, name);

    // Sign the certificate with the CA's private key using SHA-256.
    if (!X509_sign(caCert, caKey, EVP_sha256())) {
        std::cerr << "Failed to sign CA certificate" << std::endl;
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return std::make_pair("", "");
    }

    // Write the CA private key to file in PEM format.
    FILE* keyFp = fopen(keyFile.c_str(), "wb");
    if (!keyFp) {
        cerr << "Failed to open key file for writing: " << keyFile << "\n";
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return std::make_pair("", "");
    }
    if (!PEM_write_PrivateKey(keyFp, caKey, nullptr, nullptr, 0, nullptr, nullptr)) {
        cerr << "Failed to write CA private key to file" << endl;
        fclose(keyFp);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return std::make_pair("", "");
    }
    fclose(keyFp);

    // Write the CA certificate to file in PEM format.
    FILE* certFp = fopen(certFile.c_str(), "wb");
    if (!certFp) {
        cerr << "Failed to open cert file for writing: " << certFile << "\n";
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return std::make_pair("", "");
    }
    if (!PEM_write_X509(certFp, caCert)) {
        cerr << "Failed to write CA certificate to file" << endl;
        fclose(certFp);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return std::make_pair("", "");
    }
    fclose(certFp);

    // Convert the CA private key to a PEM string.
    BIO* keyBio = BIO_new(BIO_s_mem());
    PEM_write_bio_PrivateKey(keyBio, caKey, nullptr, nullptr, 0, nullptr, nullptr);
    char* keyData = nullptr;
    long keyLen = BIO_get_mem_data(keyBio, &keyData);
    std::string caKeyStr(keyData, keyLen);
    BIO_free(keyBio);

    // Convert the CA certificate to a PEM string.
    BIO* certBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509(certBio, caCert);
    char* certData = nullptr;
    long certLen = BIO_get_mem_data(certBio, &certData);
    std::string caCertStr(certData, certLen);    
    BIO_free(certBio);
    
    // Clean up
    X509_free(caCert);
    EVP_PKEY_free(caKey);

    return std::make_pair(caKeyStr, caCertStr);
}

string Server::generateCRL(const std::string& crlFile, const std::string& caKeyFile, const std::string& caCertFile, const std::string& revokedCertFile) {
    // Load the CA certificate
    FILE* caCertFp = fopen(caCertFile.c_str(), "r");
    if (!caCertFp) {
        std::cerr << "Failed to open CA certificate file: " << caCertFile << "\n";
        return "";
    }
    X509* caCert = PEM_read_X509(caCertFp, nullptr, nullptr, nullptr);
    fclose(caCertFp);
    if (!caCert) {
        std::cerr << "Failed to read CA certificate from " << caCertFile << "\n";
        return "";
    }

    // Load the CA private key
    FILE* caKeyFp = fopen(caKeyFile.c_str(), "r");
    if (!caKeyFp) {
        std::cerr << "Failed to open CA private key file: " << caKeyFile << "\n";
        X509_free(caCert);
        return "";
    }
    EVP_PKEY* caKey = PEM_read_PrivateKey(caKeyFp, nullptr, nullptr, nullptr);
    fclose(caKeyFp);
    if (!caKey) {
        std::cerr << "Failed to read CA private key from " << caKeyFile << "\n";
        X509_free(caCert);
        return "";
    }

    // Load the certificate to be revoked
    FILE* revokedCertFp = fopen(revokedCertFile.c_str(), "r");
    if (!revokedCertFp) {
        std::cerr << "Failed to open certificate to revoke: " << revokedCertFile << "\n";
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return "";
    }
    X509* revokedCert = PEM_read_X509(revokedCertFp, nullptr, nullptr, nullptr);
    fclose(revokedCertFp);
    if (!revokedCert) {
        std::cerr << "Failed to read certificate to revoke from " << revokedCertFile << "\n";
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        return "";
    }

    // Create a new CRL
    X509_CRL* crl = X509_CRL_new();
    if (!crl) {
        std::cerr << "Failed to create new CRL.\n";
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        X509_free(revokedCert);
        return "";
    }

    // Set issuer from the CA certificate
    if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert))) {
        std::cerr << "Failed to set issuer name in CRL.\n";
        X509_CRL_free(crl);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        X509_free(revokedCert);
        return "";
    }

    // Set lastUpdate and nextUpdate times
    ASN1_TIME* lastUpdate = ASN1_TIME_new();
    ASN1_TIME* nextUpdate = ASN1_TIME_new();
    ASN1_TIME_set(lastUpdate, time(nullptr));
    ASN1_TIME_set(nextUpdate, time(nullptr) + 3600); // Next update in 1 hour
    X509_CRL_set_lastUpdate(crl, lastUpdate);
    X509_CRL_set_nextUpdate(crl, nextUpdate);

    // Add the certificate to be revoked
    X509_REVOKED* revokedEntry = X509_REVOKED_new();
    if (!revokedEntry) {
        std::cerr << "Failed to create revoked entry.\n";
        X509_CRL_free(crl);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        X509_free(revokedCert);
        return "";
    }
    // Copy the serial number from the certificate to revoke
    ASN1_INTEGER* serial = X509_get_serialNumber(revokedCert);
    X509_REVOKED_set_serialNumber(revokedEntry, serial);
    ASN1_TIME* revocationDate = ASN1_TIME_new();
    ASN1_TIME_set(revocationDate, time(nullptr));
    X509_REVOKED_set_revocationDate(revokedEntry, revocationDate);
    if (!X509_CRL_add0_revoked(crl, revokedEntry)) {
        std::cerr << "Failed to add revoked entry to CRL.\n";
        X509_CRL_free(crl);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        X509_free(revokedCert);
        ASN1_TIME_free(revocationDate);
        return "";
    }
    // revokedEntry is now owned by crl

    // Sign the CRL with the CA private key
    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) {
        std::cerr << "Failed to sign the CRL.\n";
        X509_CRL_free(crl);
        X509_free(caCert);
        EVP_PKEY_free(caKey);
        X509_free(revokedCert);
        return "";
    }

    // Write the CRL to a memory BIO and extract its contents as a string
    BIO* crlBio = BIO_new(BIO_s_mem());
    PEM_write_bio_X509_CRL(crlBio, crl);
    char* crlData;
    long len = BIO_get_mem_data(crlBio, &crlData);
    std::string crlString(crlData, len);
    BIO_free(crlBio);

    // Clean up
    X509_CRL_free(crl);
    ASN1_TIME_free(lastUpdate);
    ASN1_TIME_free(nextUpdate);
    ASN1_TIME_free(revocationDate);
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    X509_free(revokedCert);

    std::cout << "CRL generated successfully." << std::endl;
    return crlString;
}

bool Server::revokeCertificate(const string& certFile, const string& crlFile, const string& caKeyFile, const string& caCertFile) {
    // Load the CA certificate
    FILE* caCertFp = fopen(caCertFile.c_str(), "r");
    if (!caCertFp) {
        cerr << "Failed to open CA certificate file: " << caCertFile << endl;
        return false;
    }
    X509* caCert = PEM_read_X509(caCertFp, nullptr, nullptr, nullptr);
    fclose(caCertFp);
    if (!caCert) {
        cerr << "Failed to load CA certificate from file: " << caCertFile << endl;
        return false;
    }

    // Load the CA private key
    FILE* caKeyFp = fopen(caKeyFile.c_str(), "r");
    if (!caKeyFp) {
        cerr << "Failed to open CA private key file: " << caKeyFile << endl;
        X509_free(caCert);
        return false;
    }
    EVP_PKEY* caKey = PEM_read_PrivateKey(caKeyFp, nullptr, nullptr, nullptr);
    fclose(caKeyFp);
    if (!caKey) {
        cerr << "Failed to load CA private key from file: " << caKeyFile << endl;
        X509_free(caCert);
        return false;
    }

    // Load the certificate to be revoked
    FILE* certFp = fopen(certFile.c_str(), "r");
    if (!certFp) {
        cerr << "Failed to open certificate file: " << certFile << endl;
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        return false;
    }
    X509* cert = PEM_read_X509(certFp, nullptr, nullptr, nullptr);
    fclose(certFp);
    if (!cert) {
        cerr << "Failed to load certificate from file: " << certFile << endl;
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        return false;
    }

    // Create a new CRL
    X509_CRL* crl = X509_CRL_new();
    if (!crl) {
        cerr << "Failed to create a new CRL." << endl;
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        X509_free(cert);
        return false;
    }

    // Set the issuer name from the CA certificate
    if (!X509_CRL_set_issuer_name(crl, X509_get_subject_name(caCert))) {
        cerr << "Failed to set issuer name in CRL." << endl;
        X509_CRL_free(crl);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        X509_free(cert);
        return false;
    }

    // Set the last update and next update fields
    ASN1_TIME* lastUpdate = ASN1_TIME_new();
    ASN1_TIME* nextUpdate = ASN1_TIME_new();
    ASN1_TIME_set(lastUpdate, time(nullptr));
    ASN1_TIME_set(nextUpdate, time(nullptr) + 3600); // Next update in 1 hour
    X509_CRL_set_lastUpdate(crl, lastUpdate);
    X509_CRL_set_nextUpdate(crl, nextUpdate);

    // Add the certificate to the CRL
    X509_REVOKED* revoked = X509_REVOKED_new();
    ASN1_INTEGER* serial = X509_get_serialNumber(cert);
    X509_REVOKED_set_serialNumber(revoked, serial);
    ASN1_TIME* revocationDate = ASN1_TIME_new();
    ASN1_TIME_set(revocationDate, time(nullptr));
    X509_REVOKED_set_revocationDate(revoked, revocationDate);
    if (!X509_CRL_add0_revoked(crl, revoked)) {
        cerr << "Failed to add revoked entry to CRL." << endl;
        X509_CRL_free(crl);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        X509_free(cert);
        ASN1_TIME_free(lastUpdate);
        ASN1_TIME_free(nextUpdate);
        ASN1_TIME_free(revocationDate);
        return false;
    }

    // Sign the CRL with the CA private key
    if (!X509_CRL_sign(crl, caKey, EVP_sha256())) {
        cerr << "Failed to sign the CRL." << endl;
        X509_CRL_free(crl);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        X509_free(cert);
        ASN1_TIME_free(lastUpdate);
        ASN1_TIME_free(nextUpdate);
        ASN1_TIME_free(revocationDate);
        return false;
    }

    // Write the CRL to a file
    FILE* crlFp = fopen(crlFile.c_str(), "wb");
    if (!crlFp) {
        cerr << "Failed to open CRL file for writing: " << crlFile << endl;
        X509_CRL_free(crl);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        X509_free(cert);
        ASN1_TIME_free(lastUpdate);
        ASN1_TIME_free(nextUpdate);
        ASN1_TIME_free(revocationDate);
        return false;
    }
    if (!PEM_write_X509_CRL(crlFp, crl)) {
        cerr << "Failed to write CRL to file: " << crlFile << endl;
        fclose(crlFp);
        X509_CRL_free(crl);
        EVP_PKEY_free(caKey);
        X509_free(caCert);
        X509_free(cert);
        ASN1_TIME_free(lastUpdate);
        ASN1_TIME_free(nextUpdate);
        ASN1_TIME_free(revocationDate);
        return false;
    }
    fclose(crlFp);

    // Clean up
    X509_free(caCert);
    EVP_PKEY_free(caKey);
    X509_free(cert);
    X509_CRL_free(crl);
    ASN1_TIME_free(lastUpdate);
    ASN1_TIME_free(nextUpdate);
    ASN1_TIME_free(revocationDate);

    return true;
}

int main() {
    try {
        Server server;
        server.start(PORT);
    } catch (const exception& e) {
        cerr << "Exception occurred: " << e.what() << endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
