cmake_minimum_required(VERSION 3.10)
project(tutorial VERSION 1.0)
set(CMAKE_CXX_STANDARD 20)

find_package(fmt REQUIRED)
find_package(Boost REQUIRED)
find_package(Threads REQUIRED)

include_directories(include)

add_executable(client client.cpp)
target_link_libraries(client fmt::fmt Threads::Threads)

add_executable(test test.cpp)
target_link_libraries(test fmt::fmt Threads::Threads)