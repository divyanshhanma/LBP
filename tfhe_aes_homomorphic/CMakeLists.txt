cmake_minimum_required(VERSION 3.10)
project(tfhe_aes_homomorphic)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

# Include headers
include_directories(
    ${PROJECT_SOURCE_DIR}/include
    ${PROJECT_SOURCE_DIR}/../tfhe/src
    ${PROJECT_SOURCE_DIR}/../tfhe/src/include
    ${PROJECT_SOURCE_DIR}/../tfhe/src/libtfhe       # tfhe headers
)

# Link directories where TFHE built libraries are
link_directories(${PROJECT_SOURCE_DIR}/../tfhe/build/libtfhe)

# Your sources
file(GLOB SOURCES src/*.cpp main.cpp)

# Executable
add_executable(main ${SOURCES})

# Link TFHE libs manually (based on what was built)
target_link_libraries(main
    tfhe-spqlios-avx
    tfhe-nayuki-avx
    tfhe-nayuki-portable
    tfhe-spqlios-fma
)
