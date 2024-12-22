cmake_minimum_required(VERSION 3.30)
project(PKI_servies)

set(CMAKE_CXX_STANDARD 20)

add_executable(PKI_servies
 ../main.cpp
 ../db/database.cpp
)

find_package(OpenSSL REQUIRED)
find_package(SQLite3 REQUIRED)
# find_package(SQLCipher REQUIRED)

include_directories(/opt/homebrew/opt/openssl/include)
link_directories(/opt/homebrew/opt/openssl/lib)

set(PROJECT_SOURCES
    ../main.cpp
)

target_link_libraries(PKI_servies OpenSSL::SSL OpenSSL::Crypto)
target_link_libraries(PKI_servies SQLite::SQLite3)
# target_link_libraries(PKI_servies sqlcipher)

# target_compile_definitions(PKI_servies PRIVATE SQLITE_HAS_CODEC)