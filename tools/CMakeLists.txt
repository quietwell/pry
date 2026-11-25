cmake_minimum_required(VERSION 3.24)
project(pry_tools CXX)

add_executable(drv_exerciser
    drv_exerciser.cpp
    cmd_mem.cpp
    cmd_ctx.cpp
    cmd_bp.cpp
    cmd_watchdog.cpp
    cmd_call.cpp
    cmd_selfprot.cpp
)
target_link_libraries(drv_exerciser PRIVATE pry_comm)
