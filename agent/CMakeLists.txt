cmake_minimum_required(VERSION 3.24)
project(pry_agent CXX)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

set(PRY_AGENT_SOURCES
    src/main.cpp
    src/breadcrumb.cpp
    src/config.cpp
    src/driver_mgr.cpp
    src/exec.cpp
    src/files.cpp
    src/listen_watch.cpp
    src/log_ring.cpp
    src/phone_home.cpp
    src/srv_log.cpp
    src/watch.cpp
    src/exec/detached.cpp
    src/exec/call_user.cpp
    src/dbg/dbg_engine.cpp
    src/dbg/dbg_process.cpp
    src/dbg/dbg_state.cpp
    src/dbg/dbg_mem.cpp
    src/dbg/dbg_bp.cpp
    src/dbg/dbg_exec.cpp
    src/dump/dumper.cpp
    src/host/host_info.cpp
    src/host/net_pin.cpp
    src/host/capture_dxgi.cpp
    src/host/capture_wgc.cpp
    src/host/window_enum.cpp
    src/host/screen_dispatch.cpp
    src/host/screen_worker.cpp
    src/pe/pe_reader.cpp
    src/pe/heap_walker.cpp
    src/service/service_main.cpp
    src/grpc/services.cpp
    src/grpc/services_common.cpp
    src/grpc/services_agent.cpp
    src/grpc/services_memory.cpp
    src/grpc/services_debug.cpp
    src/grpc/services_bp.cpp
    src/grpc/services2.cpp
    src/grpc/services_files.cpp
    src/grpc/services_exec.cpp
    src/grpc/services_registry.cpp
    src/grpc/services_watchdog.cpp
    src/grpc/services_device.cpp
    src/grpc/services_events.cpp
    src/grpc/services_cpu.cpp
    src/grpc/services_selfprot.cpp
    # v16 (Memory scanner wave 1) — on-target typed scanner (ScanService).
    # One TU; registered by main.cpp. Compiles but stays dormant until
    # services_agent.cpp sets scan_service_version to 1 (opt-in after
    # build + e2e verification — plan §2.4).
    src/scan/scan_service.cpp
    # v17 (Memory scanner wave 2) — on-target pointer map snapshot,
    # reverse pointer scan, map-vs-map diff. Shares disk_spill.hpp
    # with scan_service.cpp. Compiles but stays dormant until
    # services_agent.cpp sets pointer_map_version to 1 (plan §2.3,
    # §4 Phase L).
    src/scan/pointer_map_service.cpp
    # v17 (Memory scanner wave 2) — per-slot dissect service. Shares
    # ModuleInfo with pointer_map_service.cpp. Same opt-in gating.
    src/scan/dissect_service.cpp
    # ---- Phase R0 SI adoption landing spots ----
    # Empty stubs populated by System Informer adoption Wave 1 PRs. See
    # an internal plan §4 (Phase R0) and
    # Keeping these in CMake today means feature PRs are one-file edits
    # inside the right directory, not CMake triage.
    # Feature 1 — image coherency scoring (shared with umagent)
    src/host/img_coherency.cpp
    src/grpc/services_coherency.cpp
    # Feature 2 — hidden-process detection (shared with umagent)
    src/host/hidden_proc.cpp
    src/host/csrss_scan.cpp
    src/grpc/services_hidden.cpp
    # Feature 6 — signer / Authenticode column (shared with umagent).
    # SI README numbers this feature #8; the slice doc file-numbers it 6.
    # services_sig.cpp registers pry.Signatures on the agent view and
    # links against wintrust.lib + crypt32.lib (see link line below).
    src/host/sig_verify.cpp
    src/host/sig_cache.cpp
    src/grpc/services_sig.cpp
    # Feature 7 — user-space stack walker (shared with umagent)
    src/host/user_stackwalk.cpp
    # Feature 8 — ETW consumer + RPC surface
    src/etw/etw_session.cpp
    src/etw/etw_consumer.cpp
    src/etw/etw_registry.cpp
    src/grpc/services_etw.cpp
    # Feature 9 — process-snapshot minidump + RPC surface
    src/dump/process_dump.cpp
    src/grpc/services_dump.cpp
    # SI Wave 1 features #6 + #9 — handle ops + kernel-stack walk.
    # Both are driver-backed; the TUs are thin façades over
    # Driver::HandleDup / HandleCloseRemote / HandleCompare / StackWalk.
    src/grpc/services_handles.cpp
    src/grpc/services_stackwalk.cpp
    # service skeletons (all RPCs UNIMPLEMENTED).
    # Slice branches (P2 identity-policy, P4 process-internals) fill
    # the handlers in-place.
    src/grpc/services_token.cpp
    src/grpc/services_mitigations.cpp
    src/grpc/services_thread_inspect.cpp
    # shared GetProcessMitigationPolicy
    # readout. Vendored into umagent via its CMakeLists.
    src/host/mitigations.cpp
    # token / privilege / SID view +
    # mutator primitives. Shared with umagent (same vendor pattern as
    # sig_verify + hidden_proc).
    src/host/token_view.cpp
    src/host/token_mutate.cpp
    src/host/token_lsa.cpp
    # target_manage.reboot — reliable InitiateShutdownW wrapper.
    src/host/system_power.cpp)

add_executable(pry_agent ${PRY_AGENT_SOURCES})
add_dependencies(pry_agent pry_proto_gen pry_build_version)
target_include_directories(pry_agent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${PRY_PROTO_GEN_DIR}
    ${CMAKE_BINARY_DIR}/generated
    ${CMAKE_SOURCE_DIR}/comm
    # plain /I, not /external:I: external treatment of the vcpkg grpcpp
    # headers broke codegen visibility on this toolchain
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
target_compile_definitions(pry_agent PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
# /Z7 instead of /Zi: parallel TUs sharing one .pdb deadlock on exFAT volumes
# /bigobj (v16 Memory scanner wave 1): the ScanService addition pushed
# pry.grpc.pb.cc past MSVC's 65k-section default (error C1128).
target_compile_options(pry_agent PRIVATE /Z7 /bigobj)
target_link_libraries(pry_agent PRIVATE
    pry_comm
    pry_proto
    gRPC::grpc++
    protobuf::libprotobuf
    ole32
    advapi32
    shell32
    userenv
    ntdll
    # net_pin adapter APIs + listener self-test
    iphlpapi
    ws2_32
    # T1.1d phone-home: outbound POST to the orchestrator dashboard.
    # Ships with the Windows SDK — no vcpkg dependency.
    winhttp
    # v15 screen capture / window telemetry
    user32
    gdi32
    psapi
    d3d11
    dxgi
    dwmapi
    wtsapi32
    windowscodecs
    windowsapp
    # SI Wave 1 feature #8: signer / Authenticode column —
    # WinVerifyTrust + WTHelper* live in wintrust.lib; CertGetNameStringW
    # + CryptCATAdmin* live in crypt32.lib. Both ship with the Windows
    # SDK — no vcpkg dependency.
    wintrust
    crypt32
    # SI Wave 1 feature #14: process-snapshot minidump —
    # MiniDumpWriteDump from dbghelp.lib and the SHA256 BCryptHash*
    # digest from bcrypt.lib. PssCaptureSnapshot/PssFreeSnapshot live
    # in kernel32 (already linked by default).
    dbghelp
    bcrypt
    # SI Wave 1 feature #10: private kernel ETW session —
    # TdhGetEventInformation / TdhGetProperty live in tdh.lib; the
    # StartTrace / EnableTraceEx2 / ProcessTrace surface is in
    # advapi32 (already linked above). tdh.lib ships with the Windows
    # SDK — no vcpkg dependency.
    tdh)

# ---- C++ unit tests (no framework; registered with ctest) ----------------
# Host-only: real in-process gRPC server on 127.0.0.1 for the auth
# processor, plus pure helpers from comm/ and agent/src/. Never touches the
# driver. Run: ctest --test-dir build -C Release --output-on-failure
add_executable(pry_unit_tests tests/unit_tests.cpp)
add_dependencies(pry_unit_tests pry_proto_gen)
target_include_directories(pry_unit_tests PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/..
    ${PRY_PROTO_GEN_DIR}
    ${CMAKE_SOURCE_DIR}/comm
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
target_compile_definitions(pry_unit_tests PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
target_compile_options(pry_unit_tests PRIVATE /Z7)
target_link_libraries(pry_unit_tests PRIVATE pry_comm pry_proto gRPC::grpc++ protobuf::libprotobuf ws2_32 shell32)
add_test(NAME pry_unit_tests COMMAND pry_unit_tests)
set_tests_properties(pry_unit_tests PROPERTIES TIMEOUT 120)
