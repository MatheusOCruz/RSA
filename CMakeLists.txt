cmake_minimum_required(VERSION 3.26)
project(RSA C)

find_library(GMP_LIB gmp)
find_library(LIBSODIUM_LIB sodium)

# Adicione estas linhas para encontrar e usar a biblioteca OpenSSL
find_package(OpenSSL REQUIRED)

set(CMAKE_C_STANDARD 11)

add_executable(RSA main.c
        EAS.c
        AES.h)

# Adicione OpenSSL::Crypto para linkar a biblioteca OpenSSL
target_link_libraries(RSA ${GMP_LIB} ${LIBSODIUM_LIB} OpenSSL::Crypto)