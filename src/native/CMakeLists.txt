cmake_minimum_required(VERSION 3.20)
project(kaamo_native C)

set(CMAKE_C_STANDARD 17)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

add_library(
  kaamo
  SHARED
  cache.c
  kv_cache.c
  throttle.c
  sha256_verify.c
  seccomp_profile.c
)

target_compile_options(kaamo PRIVATE -O2 -Wall -Wextra -Werror)
find_package(OpenSSL REQUIRED)
target_link_libraries(kaamo PRIVATE OpenSSL::Crypto pthread)
set_target_properties(kaamo PROPERTIES OUTPUT_NAME "kaamo")

