cmake_minimum_required(VERSION 3.24)
project(pry_driver C ASM_MASM)

set(PRY_KMDF_VERSION "1.33" CACHE STRING "KMDF version to build against")

if(NOT PRY_WDK_ROOT)
    foreach(candidate
            "$ENV{WindowsSdkDir}"
            "C:/Program Files (x86)/Windows Kits/10"
            "C:/Program Files/Windows Kits/10"
            "D:/Windows Kits/10")
        if(candidate AND EXISTS "${candidate}/Include")
            set(PRY_WDK_ROOT "${candidate}" CACHE PATH "Windows Kits root")
            break()
        endif()
    endforeach()
endif()
if(NOT PRY_WDK_ROOT)
    message(FATAL_ERROR "Windows Kits not found; install the WDK or set -DPRY_WDK_ROOT=<path>")
endif()
message(STATUS "pry_driver: WDK root ${PRY_WDK_ROOT}")

file(GLOB PRY_SDK_VERSIONS "${PRY_WDK_ROOT}/Include/*")
set(PRY_SDK_VERSION "")
foreach(v ${PRY_SDK_VERSIONS})
    get_filename_component(name "${v}" NAME)
    if(EXISTS "${v}/km/ntddk.h" AND name MATCHES "^[0-9]")
        if(NOT PRY_SDK_VERSION OR name GREATER PRY_SDK_VERSION)
            set(PRY_SDK_VERSION "${name}")
        endif()
    endif()
endforeach()
if(NOT PRY_SDK_VERSION)
    message(FATAL_ERROR "No SDK with km headers found under ${PRY_WDK_ROOT}/Include (WDK missing?)")
endif()
set(PRY_KM_INC "${PRY_WDK_ROOT}/Include/${PRY_SDK_VERSION}/km")
set(PRY_SHARED_INC "${PRY_WDK_ROOT}/Include/${PRY_SDK_VERSION}/shared")
set(PRY_KM_LIB "${PRY_WDK_ROOT}/Lib/${PRY_SDK_VERSION}/km/x64")
set(PRY_WDF_INC "${PRY_WDK_ROOT}/Include/wdf/kmdf/${PRY_KMDF_VERSION}")

function(pry_find_wdf_lib name out)
    set(candidates
        "${PRY_WDK_ROOT}/Lib/wdf/kmdf/x64/${PRY_KMDF_VERSION}/${name}"
        "${PRY_WDK_ROOT}/Lib/${PRY_SDK_VERSION}/km/x64/${name}")
    foreach(c ${candidates})
        if(EXISTS "${c}")
            set(${out} "${c}" PARENT_SCOPE)
            return()
        endif()
    endforeach()
    message(FATAL_ERROR
        "${name} not found. Searched:\n  ${candidates}\n"
        "The WDK install appears incomplete (KMDF ${PRY_KMDF_VERSION} runtime libs missing). "
        "Re-run the WDK installer with the full 'Windows Driver Kit' feature or set PRY_KMDF_VERSION to an installed version.")
endfunction()

# modern WDK KMDF link line (WindowsDriver.KernelMode.KMDF.props):
# ntoskrnl + hal + wmilib + WdfLdr.lib + WdfDriverEntry.lib (no wdf01000)
pry_find_wdf_lib("wdfdriverentry.lib" PRY_WDFDRIVERENTRY_LIB)
pry_find_wdf_lib("wdfldr.lib" PRY_WDFLDR_LIB)

set(PRY_DRIVER_SOURCES
    src/DriverEntry.c
    src/Device.c
    src/Dispatcher.c
    src/dispatch_io.c
    src/dispatch_mem.c
    src/dispatch_proc.c
    src/dispatch_bp.c
    src/dispatch_kernel.c
    src/dispatch_watchdog.c
    src/dispatch_notify.c
    src/MemoryUser.c
    src/MemoryKernel.c
    src/KmemTrack.c
    src/Physical.c
    src/Context.c
    src/Processes.c
    src/BpList.c
    src/BpSw.c
    src/BpHw.c
    src/BpTrap.c
    src/BpTrapAsm.asm

    src/RemoteCall.c
    src/KernelCall.c
    src/Modules.c
    src/Vad.c
    src/Handles.c
    src/Pool.c
    src/Notify.c
    src/ObjDir.c
    src/Threads.c
    src/Idt.c
    src/Cpu.c
    src/Watchdog.c

    # --- SI adoption R0 landing spots (empty TUs; populated by SI Waves 1-3) ---
    # Slice 01 (driver primitives): dispatch glue extends dispatch_proc.c in-place.
    src/WaitInfo.c       # feature #3  — analyze-wait on thread
    src/IrpList.c        # slice 03 Feature 4 — KTHREAD.IrpList walker
    src/StackWalk.c      # feature #9  — kernel-stack walk primitive
    src/ProcessOpen.c    # feature #23 — protected-process open via KernelMode
    # Slice 02 (enumeration & self-protection).
    src/Callbacks.c           # feature #5  — kernel callback enumeration core
    src/CallbacksResolver.c   # feature #5  — ntoskrnl prolog pattern-scan
    src/dispatch_callbacks.c  # feature #5  — dispatcher glue
    src/SelfProt.c            # feature #21 — ObRegisterCallbacks self-protection
    src/dispatch_selfprot.c   # feature #21 — dispatcher glue
    # Slice 03 (driver infrastructure).
    src/Dyn.c                 # feature #19 — signed dynamic-offset blob
    src/dispatch_dyn.c        # feature #19 — dispatcher glue
    src/CommPort.c            # feature #20 — minifilter comm port push channel
    src/FsInformer.c          # feature #22 — minifilter FS pre-op callbacks
    src/RegInformer.c         # feature #22 — registry callback informer
    src/dispatch_informer.c   # feature #22 — FS/REG subscribe-filter IOCTLs
    src/Token.c               # feature #24 — session-token privilege model
    src/dispatch_token.c)     # feature #24 — dispatcher glue

add_library(pry_driver MODULE ${PRY_DRIVER_SOURCES})
set_target_properties(pry_driver PROPERTIES
    OUTPUT_NAME "pry_driver"
    PREFIX ""
    SUFFIX ".sys")

target_include_directories(pry_driver PRIVATE
    ${PRY_KM_INC}
    ${PRY_KM_INC}/crt
    ${PRY_SHARED_INC}
    ${PRY_WDF_INC}
    ${CMAKE_CURRENT_SOURCE_DIR})

target_compile_definitions(pry_driver PRIVATE
    _AMD64_
    AMD64
    _WIN32_WINNT=0x0A00
    NTDDI_VERSION=0x0A00000B
    KMDF_VERSION_MAJOR=1
    KMDF_VERSION_MINOR=33
    POOL_NX_OPTIN=1)

if(MSVC)
    target_compile_options(pry_driver PRIVATE
        /kernel /W4 /GS /Zp8 /GR- /EHs-c- /Oi /Z7 /FC /permissive- /volatile:metadata
        "$<$<CONFIG:Release>:/Ox>" "$<$<CONFIG:Release>:/Oy->")
    target_link_options(pry_driver PRIVATE
        /SUBSYSTEM:NATIVE /ENTRY:FxDriverEntry /NODEFAULTLIB /DRIVER /MANIFEST:NO
        /INCREMENTAL:NO /MAP /DEBUG /MACHINE:X64 /INTEGRITYCHECK)
    target_link_directories(pry_driver PRIVATE ${PRY_KM_LIB})
    target_link_libraries(pry_driver PRIVATE
        "${PRY_WDFDRIVERENTRY_LIB}"
        "${PRY_WDFLDR_LIB}"
        ntoskrnl.lib
        hal.lib
        wmilib.lib
        BufferOverflowK.lib
        ntstrsafe.lib)
endif()
