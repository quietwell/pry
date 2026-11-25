cmake_minimum_required(VERSION 3.24)
project(pry_mapper CXX)

add_executable(mapper src/main.cpp)
target_compile_definitions(mapper PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX UNICODE _UNICODE)
target_link_libraries(mapper PRIVATE pry_comm)
