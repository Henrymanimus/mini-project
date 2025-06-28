#if defined(__cplusplus)

extern "C"
{
#include "cotp.h"
#include "otpuri.h"
}

#include <cstdint>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <ctime>
#include <chrono>
#include <random>
#include <filesystem>
#include <string.h>
#include <openssl/hmac.h>
#include <windows.h>

using namespace std;

using Clock = chrono::steady_clock;

static const int32_t SHA1_BYTES = 160 / 8;   // 20
static const int32_t SHA256_BYTES = 256 / 8; // 32
static const int32_t SHA512_BYTES = 512 / 8; // 64

// byte_secret is unbase32 key
// byte_string is data to be HMAC'd
// returns 0 for failure otherwise the length of the string
int hmac_algo_sha1(const char *byte_secret, int key_length, const char *byte_string, char *out)
{
    // Output len
    unsigned int len = SHA1_BYTES;

    unsigned char *result = HMAC(
        EVP_sha1(),                               // algorithm
        (unsigned char *)byte_secret, key_length, // key
        (unsigned char *)byte_string, 8,          // data
        (unsigned char *)out,                     // output
        &len                                      // output length
    );

    // Return the HMAC success
    return result == 0 ? 0 : len;
}

int hmac_algo_sha256(const char *byte_secret, int key_length, const char *byte_string, char *out)
{
    // Output len
    unsigned int len = SHA256_BYTES;

    unsigned char *result = HMAC(
        EVP_sha256(),                             // algorithm
        (unsigned char *)byte_secret, key_length, // key
        (unsigned char *)byte_string, 8,          // data
        (unsigned char *)out,                     // output
        &len                                      // output length
    );

    // Return the HMAC success
    return result == 0 ? 0 : len;
}

int hmac_algo_sha512(const char *byte_secret, int key_length, const char *byte_string, char *out)
{
    // Output len
    unsigned int len = SHA512_BYTES;

    unsigned char *result = HMAC(
        EVP_sha512(),                             // algorithm
        (unsigned char *)byte_secret, key_length, // key
        (unsigned char *)byte_string, 8,          // data
        (unsigned char *)out,                     // output
        &len                                      // output length
    );

    // Return the HMAC success
    return result == 0 ? 0 : len;
}

// Utility: tạo timestamp string
string currentTimestamp()
{
    time_t now = time(nullptr);
    char buf[20];
    strftime(buf, sizeof(buf), "%Y%m%d%H%M%S", localtime(&now));
    return string(buf);
}

// Backup file
void backupFile(const string &filename)
{
    filesystem::create_directory("backup");
    string ts = currentTimestamp();
    filesystem::copy_file(filename, "backup/" + filename + "." + ts);
}

// Hash mật khẩu (ví dụ placeholder)
string hashPassword(const string &password, const string &salt)
{
    std::hash<string> hasher;
    return to_string(hasher(password + salt));
}

// Generate random string (salt hoặc OTP)
string randomNumeric(int length)
{
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> dis(0, 9);
    string s;
    for (int i = 0; i < length; ++i)
        s += char('0' + dis(gen));
    return s;
}

struct PersonalInfo
{
    string name;
    string email;
    string phone;
};

enum class TxStatus
{
    PENDING,
    SUCCESS,
    FAILED
};

struct Transaction
{
    string id;
    string fromWallet;
    string toWallet;
    long long amount;
    time_t timestamp;
    TxStatus status;
};

struct Wallet
{
    string id;
    long long balance;
};

struct UserAccount
{
    string username;
    string hashedPassword;
    string salt;
    bool isAdmin;
    PersonalInfo info;
    bool mustChangePassword;
    string walletId;
};

class OTPService
{
    const char *secretKey = "BASE32SECRET";
    uint32_t digits = 6;
    struct OtpEntry
    {
        string code;
        Clock::time_point expire;
    };
    unordered_map<string, OtpEntry> store;

public:
    string generate(const string &username)
    {
        OTPData otpData;
        otp_new(&otpData, secretKey, hmac_algo_sha1, digits);

        char otp_code[16] = {0};

        auto now = Clock::now();
        int64_t timeInput = chrono::duration_cast<chrono::seconds>(now.time_since_epoch()).count();
        otp_generate(&otpData, timeInput, otp_code);

        // Set OTP expiry to 2 minutes from now
        store[username] = {otp_code, now + chrono::minutes(2)};
        return otp_code;
    }
    bool verify(const string &username, const string &code)
    {
        auto it = store.find(username);
        if (it == store.end())
            return false;
        if (Clock::now() > it->second.expire)
            return false;
        return it->second.code == code;
    }
};

class Storage
{
public:
    static void saveUsers(const unordered_map<string, UserAccount> &users)
    {
        backupFile("users.dat");
        ofstream ofs("users.dat");
        for (auto &p : users)
        {
            auto &u = p.second;
            ofs << u.username << '|' << u.hashedPassword << '|' << u.salt << '|' << u.isAdmin
                << '|' << u.mustChangePassword
                << '|' << u.info.name << '|' << u.info.email << '|' << u.info.phone
                << '|' << u.walletId << "\n";
        }
    }
    static void loadUsers(unordered_map<string, UserAccount> &users)
    {
        ifstream ifs("users.dat");
        if (!ifs)
            return;
        string line;
        while (getline(ifs, line))
        {
            istringstream ss(line);
            UserAccount u;
            int admin, must;
            getline(ss, u.username, '|');
            getline(ss, u.hashedPassword, '|');
            getline(ss, u.salt, '|');
            ss >> admin;
            ss.ignore(1);
            ss >> must;
            ss.ignore(1);
            u.isAdmin = admin;
            u.mustChangePassword = must;
            getline(ss, u.info.name, '|');
            getline(ss, u.info.email, '|');
            getline(ss, u.info.phone, '|');
            getline(ss, u.walletId, '\n');
            users[u.username] = u;
        }
    }
    static void saveWallets(const unordered_map<string, Wallet> &wallets)
    {
        backupFile("wallets.dat");
        ofstream ofs("wallets.dat");
        for (auto &p : wallets)
        {
            ofs << p.first << '|' << p.second.balance << "\n";
        }
    }
    static void loadWallets(unordered_map<string, Wallet> &wallets)
    {
        ifstream ifs("wallets.dat");
        if (!ifs)
            return;
        string line;
        while (getline(ifs, line))
        {
            istringstream ss(line);
            Wallet w;
            getline(ss, w.id, '|');
            ss >> w.balance;
            wallets[w.id] = w;
        }
    }
    static void logTransaction(const Transaction &t)
    {
        ofstream ofs("transactions.log", ios::app);
        ofs << t.id << '|' << t.fromWallet << '|' << t.toWallet
            << '|' << t.amount << '|' << t.timestamp
            << '|' << int(t.status) << "\n";
    }
};

class AccountManager
{
    unordered_map<string, UserAccount> users;

public:
    AccountManager() { Storage::loadUsers(users); }
    ~AccountManager() { Storage::saveUsers(users); }

    bool registerUser(const string &username, const string &password, bool isAdmin)
    {
        if (users.count(username))
            return false;
        string salt = randomNumeric(8);
        UserAccount u;
        u.username = username;
        u.salt = salt;
        u.hashedPassword = hashPassword(password, salt);
        u.isAdmin = isAdmin;
        u.mustChangePassword = false;
        // Nhập thông tin cá nhân
        cout << "Name: ";
        getline(cin, u.info.name);
        cout << "Email: ";
        getline(cin, u.info.email);
        cout << "Phone: ";
        getline(cin, u.info.phone);
        // Tạo ví cho user
        u.walletId = "WAL" + currentTimestamp();
        users[username] = u;
        return true;
    }
    UserAccount *login(const string &username, const string &password)
    {
        auto it = users.find(username);
        if (it == users.end())
            return nullptr;
        string hashed = hashPassword(password, it->second.salt);
        if (hashed != it->second.hashedPassword)
            return nullptr;
        return &it->second;
    }
    bool changePassword(UserAccount &u, const string &newPass)
    {
        u.salt = randomNumeric(8);
        u.hashedPassword = hashPassword(newPass, u.salt);
        u.mustChangePassword = false;
        return true;
    }
    unordered_map<string, UserAccount> &getAll() { return users; }
};

class WalletManager
{
    unordered_map<string, Wallet> wallets;

public:
    WalletManager() { Storage::loadWallets(wallets); }
    ~WalletManager() { Storage::saveWallets(wallets); }

    Wallet &getWallet(const string &id)
    {
        return wallets[id];
    }
    void ensureWallet(const string &id)
    {
        if (!wallets.count(id))
            wallets[id] = {id, 0};
    }
    bool transfer(const string &from, const string &to, long long amount)
    {
        ensureWallet(from);
        ensureWallet(to);
        Wallet &A = wallets[from], &B = wallets[to];
        if (A.balance < amount)
            return false;
        // atomic in-memory
        A.balance -= amount;
        B.balance += amount;
        Transaction t;
        t.id = "TX" + currentTimestamp();
        t.fromWallet = from;
        t.toWallet = to;
        t.amount = amount;
        t.timestamp = time(nullptr);
        t.status = TxStatus::SUCCESS;
        Storage::logTransaction(t);
        return true;
    }
};

// Giao diện CLI
void mainMenu(AccountManager &am, WalletManager &wm, OTPService &otp);

int main()
{   
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    AccountManager am;
    WalletManager wm;
    OTPService otp;
    mainMenu(am, wm, otp);
    return 0;
}

void showAdminMenu()
{
    cout << "\n--- Admin Menu ---\n"
         << "1. Tạo user mới\n"
         << "2. Danh sách người dùng\n"
         << "3. Điều chỉnh thông tin user\n"
         << "4. Logout\n"
         << "Choice: ";
}

void showUserMenu()
{
    cout << "\n--- User Menu ---\n"
         << "1. Xem thông tin cá nhân\n"
         << "2. Thay đổi mật khẩu\n"
         << "3. Xem số dư và lịch sử giao dịch\n"
         << "4. Chuyển điểm\n"
         << "5. Logout\n"
         << "Choice: ";
}

void mainMenu(AccountManager &am, WalletManager &wm, OTPService &otp)
{
    while (true)
    {
        cout << "\n1. Đăng ký\n2. Đăng nhập\n3. Exit\nChoice: ";
        int c;
        cin >> c;
        cin.ignore();
        if (c == 1)
        {
            string u, p;
            bool adm;
            cout << "Username: ";
            getline(cin, u);
            cout << "Password: ";
            getline(cin, p);
            cout << "Is Admin? (0/1): ";
            cin >> adm;
            cin.ignore();
            if (am.registerUser(u, p, adm))
                cout << "Tạo thành công!";
            else
                cout << "Username đã tồn tại.";
        }
        else if (c == 2)
        {
            string u, p;
            cout << "Username: ";
            getline(cin, u);
            cout << "Password: ";
            getline(cin, p);
            UserAccount *user = am.login(u, p);
            if (!user)
            {
                cout << "Login failed.";
                continue;
            }
            if (user->mustChangePassword)
            {
                cout << "Bạn phải đổi mật khẩu ngay. Nhập mật khẩu mới: ";
                string np;
                getline(cin, np);
                am.changePassword(*user, np);
                cout << "Đổi mật khẩu thành công!";
            }
            bool logged = true;
            while (logged)
            {
                if (user->isAdmin)
                {
                    showAdminMenu();
                    int ch;
                    cin >> ch;
                    cin.ignore();
                    switch (ch)
                    {
                    case 1:
                    {
                        // create user
                        string u2, p2;
                        bool adm2;
                        cout << "New Username: ";
                        getline(cin, u2);
                        cout << "Password (auto sinh)? (Y/N): ";
                        char yn;
                        cin >> yn;
                        cin.ignore();
                        if (yn == 'Y')
                        {
                            p2 = randomNumeric(8);
                            cout << "OTP pass: " << p2 << "\n";
                        }
                        else
                        {
                            cout << "Password: ";
                            getline(cin, p2);
                        }
                        cout << "Is Admin? (0/1): ";
                        cin >> adm2;
                        cin.ignore();
                        am.registerUser(u2, p2, adm2);
                        cout << "User created.";
                        break;
                    }
                    case 2:
                    {
                        // list users
                        for (auto &p : am.getAll())
                            cout << p.first << " (" << (p.second.isAdmin ? "Admin" : "User") << ")\n";
                        break;
                    }
                    case 3:
                    {
                        cout << "Username to edit: ";
                        string eu;
                        getline(cin, eu);
                        auto &all = am.getAll();
                        if (!all.count(eu))
                        {
                            cout << "Not found\n";
                            break;
                        }
                        UserAccount &tu = all[eu];
                        cout << "New name: ";
                        getline(cin, tu.info.name);
                        cout << "New email: ";
                        getline(cin, tu.info.email);
                        cout << "New phone: ";
                        getline(cin, tu.info.phone);
                        // gửi OTP để confirm
                        string code = otp.generate(eu);
                        cout << "Mã OTP cho " << eu << ": " << code << "\n";
                        cout << "Nhập OTP: ";
                        string inp;
                        getline(cin, inp);
                        if (otp.verify(eu, inp))
                            cout << "Update thành công";
                        else
                            cout << "OTP sai. Hủy.";
                        break;
                    }
                    case 4:
                        logged = false;
                        break;
                    default:
                        cout << "Invalid";
                    }
                }
                else
                {
                    showUserMenu();
                    int ch;
                    cin >> ch;
                    cin.ignore();
                    switch (ch)
                    {
                    case 1:
                        cout << "Name: " << user->info.name << "\nEmail: " << user->info.email
                             << "\nPhone: " << user->info.phone << "\n";
                        break;
                    case 2:
                    {
                        cout << "Old password: ";
                        string op;
                        getline(cin, op);
                        if (hashPassword(op, user->salt) != user->hashedPassword)
                        {
                            cout << "Sai password\n";
                            break;
                        }
                        cout << "New password: ";
                        string np;
                        getline(cin, np);
                        am.changePassword(*user, np);
                        cout << "Đổi mật khẩu thành công\n";
                        break;
                    }
                    case 3:
                    {
                        Wallet &w = wm.getWallet(user->walletId);
                        cout << "Balance: " << w.balance << "\n";
                        // Không load lại toàn lịch sử
                        cout << "Xem file transactions.log để chi tiết.\n";
                        break;
                    }
                    case 4:
                    {
                        cout << "To Wallet ID: ";
                        string to;
                        getline(cin, to);
                        cout << "Amount: ";
                        long long amt;
                        cin >> amt;
                        cin.ignore();
                        // OTP xác nhận
                        string code = otp.generate(user->username);
                        cout << "OTP: " << code << "\n";
                        cout << "Nhập OTP: ";
                        string inp;
                        getline(cin, inp);
                        if (!otp.verify(user->username, inp))
                        {
                            cout << "OTP sai\n";
                            break;
                        }
                        if (wm.transfer(user->walletId, to, amt))
                            cout << "Chuyển thành công\n";
                        else
                            cout << "Không đủ số dư hoặc lỗi.\n";
                        break;
                    }
                    case 5:
                        logged = false;
                        break;
                    default:
                        cout << "Invalid";
                    }
                }
            }
        }
        else
            break;
    }
}

#else
#error "cotp.hpp is a C++ header. __cplusplus not defined."
#endif