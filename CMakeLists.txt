cmake_minimum_required(VERSION 3.20)
project(clck)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Boost REQUIRED COMPONENTS system url program_options)
find_package(OpenSSL REQUIRED)

add_executable(clck src/main.cpp)
target_link_libraries(clck ${Boost_LIBRARIES} OpenSSL::SSL)

install(TARGETS clck)
