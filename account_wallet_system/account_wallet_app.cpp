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
namespace fs = std::filesystem;

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
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace fs = std::filesystem;

std::string getExecutableDir() {
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string path(buffer);
    return std::filesystem::path(path).parent_path().string();
}

std::ofstream backupFile(const std::string &filename)
{
    std::string exeDir = getExecutableDir();
    fs::path backupDir = fs::path(exeDir) / "backup";
    fs::create_directories(backupDir);

    std::string ts = currentTimestamp();
    fs::path dst = backupDir / (fs::path(filename).filename().string() + "." + ts + ".txt");

    std::ofstream ofs(dst, std::ios::binary | std::ios::trunc);
    if (!ofs.is_open())
    {
        throw std::runtime_error("Không thể mở file backup: " + dst.string());
    }

    return ofs;
}

std::ifstream loadFile(const std::string &filename)
{
    fs::path backupDir{"backup"};
    const std::string prefix = filename + ".";
    const std::string suffix = ".txt";

    if (!fs::exists(backupDir) || !fs::is_directory(backupDir))
    {
        return {};
    }

    fs::path latestPath;
    std::string latestTs;

    for (const auto &entry : fs::directory_iterator(backupDir))
    {
        if (!entry.is_regular_file())
            continue;

        const auto name = entry.path().filename().string();
        if (name.rfind(prefix, 0) == 0 && name.size() > prefix.size() + suffix.size() && name.substr(name.size() - suffix.size()) == suffix)
        {
            std::string ts = name.substr(
                prefix.size(),
                name.size() - prefix.size() - suffix.size());
            if (ts > latestTs)
            {
                latestTs = ts;
                latestPath = entry.path();
            }
        }
    }

    if (latestPath.empty())
    {
        return {};
    }

    std::ifstream ifs(latestPath, std::ios::binary);
    if (!ifs.is_open())
    {
        return {};
    }

    return ifs;
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
    const char *secretKey = "JBSWY3DPEHPK3PXP"; // 16 ký tự base32 hợp lệ
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
        ofstream ofs = backupFile("users.dat");
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
        ifstream ifs = loadFile("users.dat");
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
        ofstream ofs = backupFile("wallets.dat");
        for (auto &p : wallets)
        {
            ofs << p.first << '|' << p.second.balance << "\n";
        }
    }
    static void loadWallets(unordered_map<string, Wallet> &wallets)
    {
        ifstream ifs = loadFile("wallets.dat");
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

    bool registerUser(const string &username, const string &password, bool isAdmin, bool mustChangePassword = false)
    {
        if (users.count(username))
            return false;
        string salt = randomNumeric(8);
        UserAccount u;
        u.username = username;
        u.salt = salt;
        u.hashedPassword = hashPassword(password, salt);
        u.isAdmin = isAdmin;
        u.mustChangePassword = mustChangePassword;
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
    // Thiết lập console UTF-8
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    // Khởi tạo các manager
    AccountManager am;
    WalletManager wm;
    OTPService otp;
    // Hiển thị menu chính
    mainMenu(am, wm, otp);
    return 0;
}

void showAdminMenu()
{
    cout << "\n--- Admin Menu ---\n"
         << "1. Tạo tài khoản mới\n"
         << "2. Danh sách người tài khoản\n"
         << "3. Điều chỉnh thông tin tài khoản\n"
         << "4. Đăng xuất\n"
         << "Chọn: ";
}

void showUserMenu()
{
    cout << "\n--- User Menu ---\n"
         << "1. Xem thông tin cá nhân\n"
         << "2. Thay đổi mật khẩu\n"
         << "3. Xem số dư và lịch sử giao dịch\n"
         << "4. Chuyển điểm\n"
         << "5. Đăng xuất\n"
         << "Chọn: ";
}

void confirmOTP(const string &username, OTPService &otp, const string &successMsg)
{
    string code = otp.generate(username);
    cout << "Mã OTP đã được gửi: " << code << "\n";
    int count = 0;
    while (count < 3)
    {
        cout << "Nhập mã OTP: ";
        string inp;
        getline(cin, inp);
        if (otp.verify(username, inp))
        {
            cout << successMsg;
            return;
        }
        else
        {
            cout << "Mã OTP không chính xác. Bạn còn " << (2 - count) << " lần thử.\n";
            count++;
        }
    }
    cout << "Bạn đã nhập sai quá nhiều lần. Vui lòng thử lại sau.\n";
}

void mainMenu(AccountManager &am, WalletManager &wm, OTPService &otp)
{
    while (true)
    {
        cout << "\n1. Đăng ký\n2. Đăng nhập\n3. Thoát\nChọn: ";
        int choice;
        cin >> choice;
        cin.ignore();
        if (choice == 1)
        {
            // Chức năng đăng ký
            string username, password;
            bool adm, mustChangePassword = false;
            // Nhập username
            cout << "Tên đăng nhập: ";
            getline(cin, username);
            // nhập mật khẩu
            cout << "Mật khẩu (tự sinh)? (Y/N): ";
            char yn;
            cin >> yn;
            cin.ignore();
            if (yn == 'Y' || yn == 'y')
            {
                password = randomNumeric(8);
                mustChangePassword = true; // tự động sinh thì phải đổi mật khẩu
                cout << "Mật khẩu của bạn: " << password << "\n";
            }
            else
            {
                cout << "Nhập mật khẩu: ";
                getline(cin, password);
            }
            // Nhập thông tin cá nhân
            cout << "Chọn là quyền quản trị? (0/1): ";
            cin >> adm;
            cin.ignore();
            if (am.registerUser(username, password, adm, mustChangePassword))
                cout << "Tạo thành công!";
            else
                cout << "Tài khoản đã tồn tại.";
        }
        else if (choice == 2)
        {
            // Chức năng login
            string username, password;
            // Nhập username
            cout << "Tên đăng nhập: ";
            getline(cin, username);
            // Nhập mật khẩu
            cout << "Nhập mật khẩu: ";
            getline(cin, password);

            UserAccount *user = am.login(username, password);
            // Kiểm tra đăng nhập
            if (!user)
            {
                cout << "Đăng nhập thất bại. Vui lòng thử lại.\n";
                continue;
            }
            // Kiểm tra cần đổi mật khẩu
            if (user->mustChangePassword)
            {
                cout << "Bạn phải đổi mật khẩu.\n Vui lòng nhập mật khẩu mới: ";
                string newPassword;
                getline(cin, newPassword);
                am.changePassword(*user, newPassword);
                cout << "Mật khẩu được đổi thành công!";
            }

            bool logged = true;
            while (logged)
            {
                if (user->isAdmin)
                {
                    showAdminMenu();
                    int choice;
                    cin >> choice;
                    cin.ignore();
                    switch (choice)
                    {
                    case 1:
                    {
                        // Tạo user mới
                        string username, password;
                        bool isAdmin, mustChangePassword = false;
                        cout << "Tên đăng nhập: ";
                        getline(cin, username);
                        cout << "Mật khẩu (tự sinh)? (Y/N): ";
                        char yn;
                        cin >> yn;
                        cin.ignore();
                        if (yn == 'Y' || yn == 'y')
                        {
                            password = randomNumeric(8);
                            mustChangePassword = true; // tự động sinh thì phải đổi mật khẩu
                            cout << "Mật khẩu của bạn: " << password << "\n";
                        }
                        else
                        {
                            cout << "Nhập mật khẩu: ";
                            getline(cin, password);
                        }
                        cout << "Chọn là quyền quản trị? (0/1): ";
                        cin >> isAdmin;
                        cin.ignore();
                        am.registerUser(username, password, isAdmin, mustChangePassword);
                        cout << "Đã tạo tài khoản thành công!\n";
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
                        // Chỉnh sửa thông tin user
                        cout << "\n--- Chỉnh sửa thông tin tài khoản  ---\n";
                        cout << "Nhập username: ";
                        string username;
                        getline(cin, username);
                        auto &all = am.getAll();
                        if (!all.count(username))
                        {
                            cout << "Không tìm thấy tài khoản\n";
                            break;
                        }
                        // Nhập thông tin mới
                        UserAccount &tu = all[username];
                        cout << "Nhập thông tin mới cho tài khoản " << username << ":\n";

                        cout << "Tên: ";
                        getline(cin, tu.info.name);
                        cout << "Địa chỉ email: ";
                        getline(cin, tu.info.email);
                        cout << "Số điên thoại: ";
                        getline(cin, tu.info.phone);
                        // gửi OTP để confirm
                        confirmOTP(username, otp, "Xác thực thành công. Thông tin đã được cập nhật.\n");
                        break;
                    }
                    case 4:
                    {
                        logged = false;
                        break;
                    }
                    default:
                    {
                        cout << "Không hợp lệ. Vui lòng chọn lại.\n";
                    }
                    }
                }
                else
                {
                    showUserMenu();
                    int choice;
                    cin >> choice;
                    cin.ignore();
                    switch (choice)
                    {
                    case 1:
                    {
                        // Xem thông tin cá nhân
                        cout << "\n--- Thông tin cá nhân ---\n";
                        cout << "Name: " << user->info.name
                             << "\nEmail: " << user->info.email
                             << "\nPhone: " << user->info.phone
                             << "\n";
                        break;
                    }
                    case 2:
                    {
                        // Đổi mật khẩu
                        cout << "Nhập mật khẩu cũ: ";
                        string oldPassword;
                        getline(cin, oldPassword);
                        if (hashPassword(oldPassword, user->salt) != user->hashedPassword)
                        {
                            cout << "Nhập sai mật khẩu\n";
                            break;
                        }
                        cout << "Mật khẩu mới: ";
                        string newPassword;
                        getline(cin, newPassword);
                        am.changePassword(*user, newPassword);
                        cout << "Đổi mật khẩu thành công\n";
                        break;
                    }
                    case 3:
                    {
                        // Xem số dư và lịch sử giao dịch
                        Wallet &wallet = wm.getWallet(user->walletId);
                        cout << "\n--- Xem thông tin ví ---\n";
                        cout << "Số dư: " << wallet.balance << "\n";
                        // Không load lại toàn lịch sử
                        cout << "Xem file transactions.log để chi tiết.\n";
                        break;
                    }
                    case 4:
                    {
                        // Chuyển tiền
                        // Nhập ví đích
                        cout << "\n--- Chuyển tiền ---\n";
                        cout << "Vui lòng nhập mã của ví được chuyển: ";
                        string toWalletId;
                        getline(cin, toWalletId);
                        // Nhập số tiền
                        cout << "Amount: ";
                        long long amt;
                        cin >> amt;
                        cin.ignore();
                        // gửi OTP để confirm
                        confirmOTP(user->username, otp, "Xác thực thành công. Giao dịch đã được thực hiện.\n");
                        break;
                    }
                    case 5:
                    {
                        logged = false;
                        break;
                    }
                    default:
                    {
                        cout << "Không hợp lệ. Vui lòng chọn lại.\n";
                    }
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