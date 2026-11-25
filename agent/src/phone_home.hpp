#pragma once

// T1.1d — Agent phone-home. See PLAN_FIELD_FEEDBACK_2026-10.md §T1.1d.
//
// After the gRPC listener binds, the agent spawns a detached thread that:
//   1. Enumerates its private-range IPv4 addresses via GetAdaptersAddresses.
//   2. Writes {computer_name, machine_label, port, ipv4[], boot_epoch_ms,
//      agent_instance_id, written_at} atomically to
//      C:\ProgramData\pry\agent_endpoint.json so an operator reaching
//      the box over SMB can see where the gRPC port lives today.
//   3. If orchestrator_url is non-empty, POSTs the same payload to
//      <orchestrator_url>/api/agent_report via WinHTTP (2s connect/send
//      timeouts, failure is logged via OutputDebugStringA and never
//      propagates).
//   4. Loops: re-polls adapters every 2s, re-emits on IPv4 set change,
//      otherwise re-emits every 30s as a keepalive. Never terminates.
//
// Opt-in by `--orchestrator-url <url>` or $PRY_ORCHESTRATOR_URL. Even
// with no URL set the thread still writes the local JSON file so a
// recovery operator can read the endpoint off the admin share.

#include <cstdint>
#include <string>

namespace pry {

void StartPhoneHomeThread(const std::string& orchestrator_url,
                          const std::string& computer_name,
                          const std::string& machine_label,
                          uint16_t port,
                          uint64_t boot_epoch_ms,
                          const std::string& agent_instance_id);

} // namespace pry
