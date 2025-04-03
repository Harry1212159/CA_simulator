#include "client.h"
#include "server.h"

using namespace std;

void register_user() {
    string username, password;
    cout << "Nhập tên người dùng: ";
    cin >> username;
    cout << "Nhập mật khẩu: ";
    cin >> password;
    
    if (Server::registerUser(username, password)) {
        cout << "Đăng ký thành công!" << endl;
    } else {
        cout << "Người dùng đã tồn tại!" << endl;
    }
}

void login_user() {
    string username, password;
    cout << "Nhập tên người dùng: ";
    cin >> username;
    cout << "Nhập mật khẩu: ";
    cin >> password;
    
    if (Server::authenticateUser(username, password)) {
        cout << "Đăng nhập thành công!" << endl;
    } else {
        cout << "Sai thông tin đăng nhập!" << endl;
    }
}

void request_certificate() {
    string username;
    cout << "Nhập tên người dùng để cấp chứng chỉ: ";
    cin >> username;
    
    if (Server::generateCertificate(username)) {
        cout << "Chứng chỉ đã được cấp!" << endl;
    } else {
        cout << "Không thể cấp chứng chỉ!" << endl;
    }
}

void delete_certificate() {
    string username;
    cout << "Nhập tên người dùng để xóa chứng chỉ: ";
    cin >> username;
    
    if (Server::revokeCertificate(username)) {
        cout << "Chứng chỉ đã bị thu hồi!" << endl;
    } else {
        cout << "Không tìm thấy chứng chỉ!" << endl;
    }
}

void view_certificates() {
    Server::listCertificates();
}

void verify_certificate() {
    string username;
    cout << "Nhập tên người dùng để xác minh chứng chỉ: ";
    cin >> username;
    
    if (Server::verifyCertificate(username)) {
        cout << "Chứng chỉ hợp lệ!" << endl;
    } else {
        cout << "Chứng chỉ không hợp lệ hoặc đã bị thu hồi!" << endl;
    }
}

int main() {
    while (true) {
        cout << "\nChọn chức năng:\n";
        cout << "1. Đăng ký\n";
        cout << "2. Đăng nhập\n";
        cout << "3. Cấp chứng chỉ\n";
        cout << "4. Xóa chứng chỉ\n";
        cout << "5. Xem chứng chỉ đã cấp\n";
        cout << "6. Xác minh chứng chỉ\n";
        cout << "7. Thoát\n";
        int choice;
        cin >> choice;
        
        switch (choice) {
            case 1: register_user(); break;
            case 2: login_user(); break;
            case 3: request_certificate(); break;
            case 4: delete_certificate(); break;
            case 5: view_certificates(); break;
            case 6: verify_certificate(); break;
            case 7: return 0;
            default: cout << "Lựa chọn không hợp lệ!" << endl;
        }
    }
}
