# Account Wallet System

Chương trình quản lý tài khoản và ví điểm, giao diện dòng lệnh (CLI).

## Tính năng chính
- Đăng ký tài khoản (tự nhập hoặc tự sinh mật khẩu, buộc đổi mật khẩu lần đầu nếu tự sinh)
- Đăng nhập, phân quyền người dùng và quản trị viên
- Xem/chỉnh sửa thông tin cá nhân, đổi mật khẩu
- Quản lý ví điểm: xem số dư, chuyển điểm giữa các ví
- Lưu trữ, backup dữ liệu tự động vào thư mục `backup/` với timestamp
- Xác thực hai lớp bằng OTP khi thay đổi thông tin quan trọng hoặc chuyển điểm

## Cấu trúc dữ liệu
- **UserAccount**: username, hashedPassword, salt, isAdmin, mustChangePassword, PersonalInfo (name, email, phone), walletId
- **Wallet**: id, balance
- **Transaction**: id, fromWallet, toWallet, amount, timestamp, status (PENDING, SUCCESS, FAILED)

## Quy trình sử dụng
1. **Đăng ký**: Nhập thông tin cá nhân, chọn quyền quản trị hoặc người dùng. Có thể tự sinh mật khẩu (bắt buộc đổi sau khi đăng nhập lần đầu).
2. **Đăng nhập**: Kiểm tra tài khoản, nếu cần đổi mật khẩu sẽ yêu cầu đổi ngay.
3. **Quản trị viên**:
   - Tạo tài khoản mới (tự nhập hoặc tự sinh mật khẩu)
   - Xem danh sách tài khoản
   - Chỉnh sửa thông tin tài khoản (xác thực OTP)
4. **Người dùng**:
   - Xem thông tin cá nhân
   - Đổi mật khẩu
   - Xem số dư ví, lịch sử giao dịch
   - Chuyển điểm (xác thực OTP)

## Lưu trữ & Backup
- Dữ liệu tài khoản, ví, giao dịch được lưu vào các file text (`users.dat`, `wallets.dat`, `transactions.log`)
- Mỗi lần ghi sẽ tự động backup file cũ vào thư mục `backup/` kèm timestamp

## OTP (One-Time Password)
- Sinh mã OTP 6 chữ số, thời hạn 2 phút
- OTP dùng để xác thực khi thay đổi thông tin quan trọng hoặc chuyển điểm

## Hướng dẫn chạy
1. Cài đặt các thư viện cần thiết (OpenSSL, C++17 trở lên)
2. Build project bằng CMake hoặc script build kèm theo
3. Chạy file thực thi, làm theo hướng dẫn trên CLI

## Ghi chú
- Mã nguồn sử dụng chuẩn C++17, có tích hợp thư viện mã hóa HMAC-SHA1/SHA256/SHA512 qua OpenSSL
- Dữ liệu backup giúp khôi phục khi mất mát hoặc lỗi hệ thống
- Có thể mở rộng thêm xác thực email/SMS cho OTP, nâng cấp bảo mật mật khẩu

---
