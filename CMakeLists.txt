cmake_minimum_required(VERSION 3.10)
project(account_wallet_app)

# 1) Build the COTP library
add_library(COTP STATIC
  COTP/cotp.c
  COTP/otpuri.c
)
target_include_directories(COTP PUBLIC
  ${PROJECT_SOURCE_DIR}/COTP
)
find_package(OpenSSL REQUIRED)
target_link_libraries(COTP PUBLIC OpenSSL::Crypto)

# 2) Then build the executable
add_executable(account_wallet_app
  account_wallet_system/account_wallet_app.cpp
)

# 3) Now you can safely set includes and link libraries
target_include_directories(account_wallet_app PRIVATE
  ${PROJECT_SOURCE_DIR}/COTP
)
target_link_libraries(account_wallet_app PRIVATE
  COTP
  OpenSSL::Crypto
)