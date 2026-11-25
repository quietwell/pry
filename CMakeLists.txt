cmake_minimum_required(VERSION 3.24)
project(pry LANGUAGES C CXX)

set(CMAKE_C_STANDARD 17)
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)

# static CRT everywhere: matches the vcpkg static triplets
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

option(PRY_BUILD_DRIVER "Build pry_driver.sys (requires WDK)" ON)

# build version stamp: git sha + dirty flag baked into agent_version so a
# deployed binary reports which commit it came from (update_target.py checks)
#
# Previously generated once via configure_file at `cmake -S . -B build`
# time, so every `cmake --build` after a branch switch stamped the stale
# configure-time SHA onto new binaries. Now rebuilt on every build via a
# custom target invoking cmake/refresh_build_version.cmake; the script
# only rewrites build_version.h when the stamp actually changed, so TUs
# that include it don't recompile unnecessarily.
set(PRY_BUILD_VERSION_H ${CMAKE_CURRENT_BINARY_DIR}/generated/build_version.h)
# Prime the header once so first-build TUs find it (the custom target
# runs via ALL on every build and will refresh it from HEAD).
if(NOT EXISTS ${PRY_BUILD_VERSION_H})
    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/generated)
    file(WRITE ${PRY_BUILD_VERSION_H}
         "#pragma once\n#define PRY_GIT_SHA \"nogit\"\n#define PRY_GIT_DIRTY \"\"\n")
endif()
add_custom_target(pry_build_version ALL
    BYPRODUCTS ${PRY_BUILD_VERSION_H}
    COMMAND ${CMAKE_COMMAND}
        -DPRY_SOURCE_DIR=${CMAKE_CURRENT_SOURCE_DIR}
        -DPRY_BUILD_VERSION_IN=${CMAKE_CURRENT_SOURCE_DIR}/cmake/build_version.h.in
        -DPRY_BUILD_VERSION_H=${PRY_BUILD_VERSION_H}
        -P ${CMAKE_CURRENT_SOURCE_DIR}/cmake/refresh_build_version.cmake
    COMMENT "pry: refreshing build_version.h from current HEAD"
    VERBATIM)

# C++ gRPC stubs from proto/pry.proto via vcpkg protoc + grpc_cpp_plugin
find_package(protobuf CONFIG QUIET)
find_package(gRPC CONFIG QUIET)
if(protobuf_FOUND AND gRPC_FOUND)
    set(PRY_PROTO_DIR ${CMAKE_CURRENT_SOURCE_DIR}/proto)
    set(PRY_PROTO_GEN_DIR ${CMAKE_CURRENT_BINARY_DIR}/proto_gen)
    file(MAKE_DIRECTORY ${PRY_PROTO_GEN_DIR})

    get_target_property(protoc_executable protobuf::protoc IMPORTED_LOCATION_RELEASE)
    if(NOT protoc_executable)
        get_target_property(protoc_executable protobuf::protoc IMPORTED_LOCATION)
    endif()
    find_program(grpc_cpp_plugin_executable grpc_cpp_plugin HINTS "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/tools/grpc" REQUIRED)

    set(PRY_PROTO_SRCS "${PRY_PROTO_GEN_DIR}/pry.pb.cc" "${PRY_PROTO_GEN_DIR}/pry.grpc.pb.cc")
    set(PRY_PROTO_HDRS "${PRY_PROTO_GEN_DIR}/pry.pb.h" "${PRY_PROTO_GEN_DIR}/pry.grpc.pb.h")

    add_custom_command(
        OUTPUT ${PRY_PROTO_SRCS} ${PRY_PROTO_HDRS}
        COMMAND ${CMAKE_COMMAND} -E echo "Generating C++ gRPC stubs from pry.proto"
        COMMAND ${protoc_executable}
                --grpc_out=${PRY_PROTO_GEN_DIR}
                --cpp_out=${PRY_PROTO_GEN_DIR}
                -I ${PRY_PROTO_DIR}
                --plugin=protoc-gen-grpc=${grpc_cpp_plugin_executable}
                ${PRY_PROTO_DIR}/pry.proto
        DEPENDS ${PRY_PROTO_DIR}/pry.proto
        USES_TERMINAL)
    set_source_files_properties(${PRY_PROTO_SRCS} PROPERTIES GENERATED TRUE)
    add_custom_target(pry_proto_gen ALL DEPENDS ${PRY_PROTO_SRCS})

    # One compiled copy of the generated stubs, shared by the agent, the
    # umagent and the C++ unit tests (pry.grpc.pb.cc is /bigobj-sized;
    # compiling it once per consumer was the slowest part of the build).
    add_library(pry_proto STATIC ${PRY_PROTO_SRCS} ${PRY_PROTO_HDRS})
    add_dependencies(pry_proto pry_proto_gen)
    target_include_directories(pry_proto PUBLIC
        ${PRY_PROTO_GEN_DIR}
        "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
    # /Z7: see agent/CMakeLists.txt (shared-.pdb deadlock on exFAT)
    target_compile_options(pry_proto PRIVATE /Z7 /bigobj)
    target_link_libraries(pry_proto PUBLIC gRPC::grpc++ protobuf::libprotobuf)
else()
    message(STATUS "gRPC/protobuf not found: agent target will be skipped (run vcpkg install grpc:x64-windows-static)")
endif()

# C++ unit tests (comm struct asserts, pattern-scan loop, auth processor, ...)
# register with ctest from their subdirectories: `ctest --test-dir build -C Release`
enable_testing()

if(PRY_BUILD_DRIVER)
    add_subdirectory(driver)
endif()
add_subdirectory(comm)
add_subdirectory(tools)
add_subdirectory(mapper)
if(protobuf_FOUND AND gRPC_FOUND)
    add_subdirectory(agent)
    add_subdirectory(umagent)
endif()
