cmake_minimum_required(VERSION 3.24)
project(pry_umagent CXX)

find_package(Protobuf CONFIG REQUIRED)
find_package(gRPC CONFIG REQUIRED)

set(PRY_UMAGENT_SOURCES
    src/main.cpp
    src/umem.cpp
    src/um_services.cpp
    # Phase R0 — SI adoption landing spots (empty TUs, populated by Wave 1 PRs;
    # see an internal plan §4 and
    # an internal plan).
    # Feature #1 — image coherency scoring (umagent facade + shared scorer)
    src/img_coherency.cpp
    src/services_coherency.cpp
    ../agent/src/host/img_coherency.cpp
    # Feature #2 — hidden-process detection (Wave 1 modes:
    # brute / registry / ETW). Shared scanner vendored in from
    # agent/src/host/hidden_proc.cpp; services_hidden.cpp exposes
    # the Scan RPC on the umagent view.
    src/hidden_proc.cpp
    src/services_hidden.cpp
    ../agent/src/host/hidden_proc.cpp
    # Feature #3 — analyze-wait on thread
    src/syscall_table.cpp
    src/wait_decode.cpp
    # Feature #6 — signer + Authenticode column (shared with agent).
    # Shared probe lives in agent/src/host/sig_verify.cpp +
    # agent/src/host/sig_cache.cpp (vendored like img_coherency); the
    # local sig_verify.cpp / sig_cache.cpp TUs are thin facades that
    # alias into pry::host so umagent code keeps its ``um::`` prefix.
    src/sig_verify.cpp
    src/sig_cache.cpp
    src/services_sig.cpp
    ../agent/src/host/sig_verify.cpp
    ../agent/src/host/sig_cache.cpp
    # Feature #7 — kernel-stack walk primitive (user-side)
    src/user_stackwalk.cpp
    # Feature #8 — ETW start/consume kernel session (SI README #10).
    # umagent-local TUs are empty facades; the real StartTrace +
    # ProcessTrace + SPSC ring + TDH decoder live in the agent tree
    # and are vendored into the umagent build (same pattern as
    # img_coherency / sig_verify).
    src/etw/etw_session.cpp
    src/etw/etw_consumer.cpp
    src/etw/etw_registry.cpp
    src/services_etw.cpp
    ../agent/src/etw/etw_session.cpp
    ../agent/src/etw/etw_consumer.cpp
    ../agent/src/etw/etw_registry.cpp
    # Feature #9 — process-snapshot minidump (SI README feature #14).
    # Shared impl lives in agent/src/dump/process_dump.cpp (same vendor
    # pattern as sig_verify / img_coherency); the local TU is a facade.
    src/dump/process_dump.cpp
    src/services_dump.cpp
    ../agent/src/dump/process_dump.cpp
    # live kernel dump via
    # NtSystemDebugControl(SysDbgGetLiveKernelDump). Umagent-only (the
    # agent view returns kind='not_supported' with hint='use name=user').
    src/dump/live_kernel_dump.cpp
    # service skeletons (all RPCs UNIMPLEMENTED).
    # Slice branches (P2 identity-policy, P3 external-inventory,
    # P4 process-internals) fill the handlers in-place.
    src/services_token.cpp
    src/services_mitigations.cpp
    src/services_network.cpp
    src/services_services.cpp
    src/services_thread_inspect.cpp
    # desktop input injection (SendInput-backed Click / Type /
    # Key). umagent-only; see services_input.cpp for the session-guard +
    # trust rationale.
    src/services_input.cpp
    # vendored
    # GetProcessMitigationPolicy decoder shared with the agent.
    ../agent/src/host/mitigations.cpp
    # vendored token view / mutate /
    # LSA helpers shared with the agent (same pattern as sig_verify).
    ../agent/src/host/token_view.cpp
    ../agent/src/host/token_mutate.cpp
    ../agent/src/host/token_lsa.cpp
    # build-independent PE walker shared with the agent (imports/exports)
    ../agent/src/pe/pe_reader.cpp
    # shared param-block trampoline call (CALL_USER) — same TU as the agent
    ../agent/src/exec/call_user.cpp
    # shared rotating log + listener self-test
    ../agent/src/srv_log.cpp
    ../agent/src/listen_watch.cpp
    # v16 (Memory scanner wave 1): shared on-target scan engine. umagent
    # supplies its own ReadProcessMemory-backed MemReadFn; agent
    # supplies a driver-backed one. Dormant until scan_service_version
    # is flipped to 1 in um_services.cpp — build-verify first.
    ../agent/src/scan/scan_service.cpp
    # v17 (Memory scanner wave 2): shared on-target pointer map engine +
    # reverse scan + diff. Same shared-TU vendor pattern as
    # scan_service.cpp. Dormant until pointer_map_version is flipped
    # to 1 in um_services.cpp.
    ../agent/src/scan/pointer_map_service.cpp
    # v17 (Memory scanner wave 2): shared dissect scorer + handler.
    ../agent/src/scan/dissect_service.cpp)

add_executable(pry_umagent ${PRY_UMAGENT_SOURCES})
add_dependencies(pry_umagent pry_proto_gen pry_build_version)
target_include_directories(pry_umagent PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/pe
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src/exec
    ${CMAKE_CURRENT_SOURCE_DIR}/../agent/src
    ${PRY_PROTO_GEN_DIR}
    ${CMAKE_BINARY_DIR}/generated
    # comm/grpc_auth.hpp (header-only shared bearer check) and the
    # header-only comm helpers; umagent does not link pry_comm.
    ${CMAKE_SOURCE_DIR}/comm
    # plain /I, not /external:I: external treatment of the vcpkg grpcpp
    # headers broke codegen visibility on this toolchain (same as agent)
    "${VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}/include")
target_compile_definitions(pry_umagent PRIVATE WIN32_LEAN_AND_MEAN NOMINMAX _CRT_SECURE_NO_WARNINGS)
# /Z7 instead of /Zi: parallel TUs sharing one .pdb deadlock on exFAT volumes
target_compile_options(pry_umagent PRIVATE /Z7 /bigobj)
target_link_libraries(pry_umagent PRIVATE
    pry_proto
    gRPC::grpc++
    protobuf::libprotobuf
    advapi32
    # SendInput + MapVirtualKeyW + VkKeyScanW live in user32,
    # WTSGetActiveConsoleSessionId in wtsapi32.
    user32
    wtsapi32
    # listener self-test loopback probes
    ws2_32
    # SI Wave 1 feature #8: signer / Authenticode column —
    # WinVerifyTrust + WTHelper* in wintrust.lib, CertGetNameString +
    # CryptCATAdmin* in crypt32.lib. Both ship with the Windows SDK.
    wintrust
    crypt32
    # SI Wave 1 feature #14: process-snapshot minidump —
    # MiniDumpWriteDump lives in dbghelp.lib; PssCaptureSnapshot &
    # friends in kernel32.lib (linked by default); SHA256 digest via
    # BCryptHash* in bcrypt.lib.
    dbghelp
    bcrypt
    # SI Wave 1 feature #10: private kernel ETW session —
    # TdhGetEventInformation / TdhGetProperty live in tdh.lib; the
    # StartTrace / EnableTraceEx2 / ProcessTrace surface is in
    # advapi32 (already linked above).
    tdh
    # SI Wave 1 feature #2: hidden-process detection — the
    # registry mode uses psapi.EnumProcesses + QueryFullProcessImageName
    # to map image names to PIDs.
    psapi
    # SI Wave 1 feature #3: syscall-number calibration pulls
    # ntdll.dll's VS_FIXEDFILEINFO via GetFileVersionInfo* for the
    # umagent-visible ntdll build tag.
    version)
