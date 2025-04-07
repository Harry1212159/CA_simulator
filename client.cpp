#include "client.h"
#include <iostream>
#include <unistd.h>
#include <arpa/inet.h>
#include <cstring>

#define PORT 8080
#define SERVER_IP "127.0.0.1"

// Function to send a message to the server and receive a response
void communicateWithServer(int sock, const std::string &message) {
    // Send the message to the server
    if (send(sock, message.c_str(), message.size(), 0) < 0) {
        perror("Send failed");
        return;
    }

    // Buffer to store the server's response
    char buffer[4096] = {0};
    int bytesRead = read(sock, buffer, sizeof(buffer));
    if (bytesRead > 0) {
        std::cout << "Server: " << std::string(buffer, bytesRead) << std::endl;
    } else {
        std::cout << "Server disconnected or read error occurred." << std::endl;
    }
}

void clientRegister(int sock) {
    std::string username, password;
    std::cout << "Enter username for registration: ";
    std::getline(std::cin, username);
    std::cout << "Enter password for registration: ";
    std::getline(std::cin, password);

    std::string message = "REGISTER " + username + " " + password;
    communicateWithServer(sock, message);
    // cout << message << endl;
}

void clientLogin(int sock) {
    std::string username, password;
    std::cout << "Enter username for login: ";
    std::getline(std::cin, username);
    std::cout << "Enter password for login: ";
    std::getline(std::cin, password);

    std::string message = "LOGIN " + username + " " + password;
    communicateWithServer(sock, message);
}

bool generateCSR(const string& username, const std::string& commonName, const std::string& organization,
    const std::string& country) {
    // Initialize OpenSSL algorithms
    std::string csrFile = username + "_certificate.pem";
    std::string keyFile = username + "_private.key";
    OpenSSL_add_all_algorithms();

    // Generate RSA Key using EVP APIs
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Error creating EVP_PKEY_CTX." << std::endl;
        return false;
    }
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing keygen." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Error setting RSA keygen bits." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }

    EVP_PKEY* pKey = nullptr;
    if (EVP_PKEY_generate(ctx, &pKey) <= 0) {
        std::cerr << "Error generating RSA key pair." << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    EVP_PKEY_CTX_free(ctx); // Done with the context

    // Create a new X509_REQ (CSR) object
    X509_REQ* x509Req = X509_REQ_new();
    if (!x509Req) {
        std::cerr << "Error creating X509_REQ." << std::endl;
        EVP_PKEY_free(pKey);
        return false;
    }

    // Create and set the subject name
    X509_NAME* name = X509_NAME_new();
    if (!name) {
        std::cerr << "Error creating X509_NAME." << std::endl;
        X509_REQ_free(x509Req);
        EVP_PKEY_free(pKey);
        return false;
    }
    if (!X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(country.c_str()), -1, -1, 0)) {
        std::cerr << "Error adding Country to subject name." << std::endl;
    }
    if (!X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(organization.c_str()), -1, -1, 0)) {
        std::cerr << "Error adding Organization to subject name." << std::endl;
    }
    if (!X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
            reinterpret_cast<const unsigned char*>(commonName.c_str()), -1, -1, 0)) {
        std::cerr << "Error adding Common Name to subject name." << std::endl;
    }
    if (X509_REQ_set_subject_name(x509Req, name) != 1) {
        std::cerr << "Error setting subject name in CSR." << std::endl;
        X509_NAME_free(name);
        X509_REQ_free(x509Req);
        EVP_PKEY_free(pKey);
        return false;
    }
    X509_NAME_free(name); // Subject name now copied into x509Req

    // Set the public key in the CSR
    if (X509_REQ_set_pubkey(x509Req, pKey) != 1) {
        std::cerr << "Error setting public key in CSR." << std::endl;
        X509_REQ_free(x509Req);
        EVP_PKEY_free(pKey);
        return false;
    }

    // Sign the CSR with the private key using SHA-256
    if (X509_REQ_sign(x509Req, pKey, EVP_sha256()) <= 0) {
        std::cerr << "Error signing the CSR." << std::endl;
        X509_REQ_free(x509Req);
        EVP_PKEY_free(pKey);
        return false;
    }

    // Write the private key to a file
    FILE* pKeyFile = fopen(keyFile.c_str(), "wb");
    if (!pKeyFile) {
        std::cerr << "Error opening file to write private key." << std::endl;
        X509_REQ_free(x509Req);
        EVP_PKEY_free(pKey);
        return false;
    }
    PEM_write_PrivateKey(pKeyFile, pKey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(pKeyFile);

    // Write the CSR to a file
    FILE* csrOut = fopen(csrFile.c_str(), "wb");
    if (!csrOut) {
        std::cerr << "Error opening file to write CSR." << std::endl;
        X509_REQ_free(x509Req);
        EVP_PKEY_free(pKey);
        return false;
    }
    PEM_write_X509_REQ(csrOut, x509Req);
    fclose(csrOut);

    // Clean up
    EVP_PKEY_free(pKey);
    X509_REQ_free(x509Req);

    return true;
}

void clientRequestCertificate(int sock) {
    std::string username;
    std::cout << "Enter username to request certificate: ";
    std::getline(std::cin, username);

    // Construct the CSR file name
    std::string csrFile = generateCSR(username, "example.com", "Example Org", "US") ? username + "_certificate.pem" : "";
    // Read the CSR file
    std::ifstream csrStream(csrFile);
    if (!csrStream.is_open()) {
        std::cerr << "Failed to open CSR file: " << csrFile << std::endl;
        return;
    }

    // Read the entire CSR content
    std::string csrContent((std::istreambuf_iterator<char>(csrStream)),
                           std::istreambuf_iterator<char>());
    csrStream.close();

    // Construct the message to send to the server
    std::string message = "CERT " + username + "\n" + csrContent;

    // Send the message to the server
    if (send(sock, message.c_str(), message.size(), 0) < 0) {
        perror("Failed to send CSR to server");
        return;
    }

    // Receive the signed certificate from the server
    char buffer[4096] = {0};
    int bytesRead = read(sock, buffer, sizeof(buffer));
    if (bytesRead > 0) {
        std::string response(buffer, bytesRead);

        // Check if the response contains the signed certificate
        if (response.find("CERTIFICATE\n") == 0) {
            std::string signedCert = response.substr(12); // Extract the certificate content

            // Save the signed certificate to a file
            std::string certFile = username + "_signed_certificate.pem";
            std::ofstream certStream(certFile);
            if (certStream.is_open()) {
                certStream << signedCert;
                certStream.close();
                std::cout << "Signed certificate saved to: " << certFile << std::endl;
            } else {
                std::cerr << "Failed to save signed certificate to file." << std::endl;
            }
        } else {
            std::cerr << "Server response: " << response << std::endl;
        }
    } else {
        perror("Failed to receive response from server");
    }
}

void clientMenu(int sock) {
    while (true) {
        std::cout << "\n--- Client Menu ---\n";
        std::cout << "1. Register\n";
        std::cout << "2. Login\n";
        std::cout << "3. Request Certificate\n";
        std::cout << "4. Exit\n";
        std::cout << "Enter your choice: ";

        std::string choice;
        std::getline(std::cin, choice);

        if (choice == "1") {
            clientRegister(sock);
        } else if (choice == "2") {
            clientLogin(sock);
        } else if (choice == "3") {
            clientRequestCertificate(sock);
        } else if (choice == "4") {
            std::cout << "Exiting client." << std::endl;
            break;
        } else {
            std::cout << "Invalid choice. Please try again.\n";
        }
    }
}

int main() {
    // Create a socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation error");
        return -1;
    }

    // Define the server address
    struct sockaddr_in serv_addr;
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(PORT);

    // Convert IPv4 and IPv6 addresses from text to binary form
    if (inet_pton(AF_INET, SERVER_IP, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return -1;
    }

    // Connect to the server
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }

    std::cout << "Connected to server." << std::endl;

    // Start the client menu
    clientMenu(sock);

    // Close the socket when done
    close(sock);
    return 0;
}
