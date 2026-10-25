cmake_minimum_required(VERSION 3.16)
project(pactool C)

set(CMAKE_C_STANDARD 99)
set(CMAKE_C_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

add_executable(pactool pactool.c)
target_compile_options(pactool PRIVATE -Wall -Wextra)
install(TARGETS pactool RUNTIME DESTINATION bin)
