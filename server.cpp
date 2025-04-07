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

void Server::storeUserCredentials(const std::string& username, const std::string& password) {
    // Ensure the "users" directory exists
    std::filesystem::create_directories("users");
    std::cout << "Current working directory: " << std::filesystem::current_path() << std::endl;

    // Create the filename for the user's credentials
    std::string filename = "users/" + username + ".txt";

    // Open the file for writing
    std::ofstream ofs(filename);
    if (!ofs.is_open()) {
        std::cerr << "Failed to open " << filename << " for writing." << std::endl;
        return;
    }
    
    // Write the username and password (each on a separate line)
    ofs << username << "\n" << password << "\n";
    ofs.close();
    std::cout << "Stored credentials for user '" << username << "'." << std::endl;
}


// Registration: creates a file for the new user if it doesn't already exist
void Server::registerUser(const string &username, const string &password) {
    string filename = "users/" + username + ".txt";
    if (std::filesystem::exists(filename)) {
        cout << "Registration failed: User '" << username << "' already exists." << endl;
        return;
    }
    storeUserCredentials(username, password);
    cout << "Registration successful for user '" << username << "'." << endl;
}

// Authentication: reads the file for the given username and checks the stored password
bool Server::authenticateUser(const string &username, const string &password) {
    string filename = "users/" + username + ".txt";
    if (!std::filesystem::exists(filename)) {
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
            bool existedBefore = std::filesystem::exists(filename);
            registerUser(username, password);
            if (std::filesystem::exists(filename) && !existedBefore) {
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
            std::string csrContent = request.substr(request.find('\n') + 1);
            std::cout << "Received CSR content for user: " << username << std::endl;

            // Sign the CSR
            std::string signedCert = signCSR(username, csrContent);
            if (!signedCert.empty()) {
                response = "CERTIFICATE\n" + signedCert;
            } else {
                response = "Certificate generation failed.";
            }

            // Send the signed certificate back to the client
            send(client_socket, response.c_str(), response.size(), 0);
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

std::string Server::signCSR(const string& username, const std::string& csrContent) {
    BIO* csrBIO = BIO_new_mem_buf(csrContent.c_str(), -1);
    X509_REQ* req = PEM_read_bio_X509_REQ(csrBIO, NULL, NULL, NULL);
    if (!req) {
        std::cerr << "Failed to parse CSR\n";
        BIO_free(csrBIO);
        return "";
    }

    string keyFilePath = "./" + username + "_private.key";
    string certFilePath = "./" + username + "_certificate.pem";
    // Load CA private key and certificate (you should have these stored securely)
    FILE* keyFile = fopen(keyFilePath.c_str(), "r");
    FILE* certFile = fopen(certFilePath.c_str(), "r");

    if (!keyFile || !certFile) {
        std::cerr << "Failed to open CA key or certificate for user: " << username << "\n";
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
        std::cerr << "Failed to load CA key or certificate for user: " << username << "\n";
        if (caKey) EVP_PKEY_free(caKey);
        if (caCert) X509_REQ_free(caCert);
        BIO_free(csrBIO);
        return "";
    }

    // Create a new certificate
    X509* newCert = X509_new();
    if (!newCert) {
        std::cerr << "Failed to create new X509 certificate.\n";
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
        std::cerr << "Failed to set issuer name.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        BIO_free(csrBIO);
        return "";
    }

    // Set subject from CSR
    if (!X509_set_subject_name(newCert, X509_REQ_get_subject_name(req))) {
        std::cerr << "Failed to set subject name from CSR.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        X509_REQ_free(req);
        BIO_free(csrBIO);
        return "";
    }

    EVP_PKEY* reqPubKey = X509_REQ_get_pubkey(req);
    if (!reqPubKey || !X509_set_pubkey(newCert, reqPubKey)) {
        std::cerr << "Failed to set public key from CSR.\n";
        EVP_PKEY_free(caKey);
        X509_REQ_free(caCert);
        X509_free(newCert);
        X509_REQ_free(req);
        BIO_free(csrBIO);
        return "";
    }

    // Sign the certificate
    if (!X509_sign(newCert, caKey, EVP_sha256())) {
        std::cerr << "Signing failed for user: " << username << "\n";
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
    std::string signedCert(certData, len);

    // Clean up
    EVP_PKEY_free(caKey);
    X509_REQ_free(caCert);
    X509_free(newCert);
    X509_REQ_free(req);
    BIO_free(out);
    BIO_free(csrBIO);

    return signedCert;
}


bool sendWithLength(int socket, const std::string& data) {
    uint32_t length = htonl(data.size());
    if (send(socket, &length, sizeof(length), 0) != sizeof(length)) return false;
    if (send(socket, data.c_str(), data.size(), 0) != (ssize_t)data.size()) return false;
    return true;
}
// bool Server::revokeCertificate(const string& username) {
//     auto it = userDatabase.find(username);
//     if (it == userDatabase.end() || it->second.certificate.empty()) {
//         return false; // User not found or no certificate issued
//     }

//     // Paths to the certificate and CA configuration
//     string certPath = "/path/to/certificates/" + username + ".pem";
//     string caConfigPath = "/path/to/openssl.cnf";

//     // Revoke the certificate
//     string revokeCmd = "openssl ca -config " + caConfigPath + " -revoke " + certPath;
//     int revokeResult = system(revokeCmd.c_str());
//     if (revokeResult != 0) {
//         return false; // Revocation failed
//     }

//     // Generate a new CRL
//     string crlPath = "/path/to/crl.pem";
//     string genCrlCmd = "openssl ca -config " + caConfigPath + " -gencrl -out " + crlPath;
//     int crlResult = system(genCrlCmd.c_str());
//     if (crlResult != 0) {
//         return false; // CRL generation failed
//     }

//     // Optionally, update the user's record in the database
//     it->second.certificate.clear();

//     return true;
// }

int main() {
    try {
        Server server;
        server.start(PORT);
    } catch (const std::exception& e) {
        std::cerr << "Exception occurred: " << e.what() << std::endl;
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
