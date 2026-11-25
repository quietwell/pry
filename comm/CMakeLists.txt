cmake_minimum_required(VERSION 3.24)
project(pry_comm CXX)

# Phase 7c: pry_comm.cpp was split into per-concern TUs. The original
# pry_comm.cpp stays as a facade holding the ABI compile-time guards;
# every function moved to a peer TU. pry_comm.h is unchanged.
add_library(pry_comm STATIC
    pry_comm.cpp
    pry_comm_core.cpp
    pry_comm_mem.cpp
    pry_comm_ctx.cpp
    pry_comm_bp.cpp
    pry_comm_watchdog.cpp
    pry_comm_notify.cpp
    pry_comm_cpu.cpp
    pry_comm.h
    pry_comm_internal.hpp
    pry_abi.h)
target_include_directories(pry_comm PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_compile_definitions(pry_comm PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS UNICODE)
