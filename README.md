 * account_wallet_system.cpp
 *
 * Chương trình quản lý tài khoản và ví điểm, giao diện văn bản (CLI).
 *
 * Thiết kế:
 *
 * 1. Lớp UserAccount:
 *    - username: string (không thay đổi sau khi tạo)
 *    - hashedPassword: string (lưu mật khẩu dưới dạng băm)
 *    - salt: string (dùng cho hàm băm)
 *    - isAdmin: bool
 *    - personalInfo: struct { name, email, phone, ... }
 *    - mustChangePassword: bool (nếu mật khẩu tự sinh)
 *
 * 2. Lớp Wallet:
 *    - id: string (UUID hoặc mã sinh tự động)
 *    - balance: long long
 *
 * 3. Lớp Transaction:
 *    - id: string
 *    - fromWallet, toWallet: string
 *    - amount: long long
 *    - timestamp: time_t
 *    - status: enum { PENDING, SUCCESS, FAILED }
 *
 * 4. Lớp AccountManager:
 *    - users: map<string, UserAccount>
 *    - load/save users từ một tập tin duy nhất ("users.dat")
 *    - backup tự động: copy "users.dat" vào thư mục "backup/" mỗi khi ghi
 *
 * 5. Lớp OTPService:
 *    - map<string, pair<string, time_point>> otpStore;
 *    - generateOTP(username)
 *    - verifyOTP(username, code)
 *
 * 6. Lớp WalletManager:
 *    - wallets: map<string, Wallet>
 *    - transactions: vector<Transaction>
 *    - load/save wallets và log giao dịch ("wallets.dat", "transactions.log")
 *    - transferAtomic(from, to, amount) đảm bảo atomic bằng cách xử lý trong memory rồi lưu
 *
 * 7. Lưu trữ file đơn giản: mỗi loại dữ liệu 1 file text, dễ quản lý và backup.
 *    - Backup: copy file với timestamp.
 *
 * 8. Băm mật khẩu: dùng std::hash<string> + salt (tham khảo bcrypt hoặc SHA256 cho thực tế).
 *
 * 9. OTP cho xác thực hai lớp (thay đổi thông tin, chuyển điểm): tạo 6 chữ số, thời gian sống 5 phút.
 *
 * Phần chính: giao diện menu CLI, phân quyền người dùng thường và quản lý.
