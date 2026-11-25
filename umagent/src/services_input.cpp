// umagent/src/services_input.cpp — desktop input injection.
//
// Implements the pry.Input service (Click / Type / Key) on the umagent
// view. umagent runs in the interactive session (session 1), so SendInput
// reaches the user desktop; the session-0 agent service cannot serve these
// RPCs — SendInput from a session-0 service never surfaces.
//
// Trust gate: actuator trust is enforced on the ORCHESTRATOR side via
// _check_actuator_trust in orchestrator/src/pry/mcp/tools/_runtime/
// guard.py, driven by capability-registry entries marked
// gate='min_trust_actuator'. The umagent view has no local notion of
// machine trust (um::Config carries none), so the `force` flag on the
// request messages is accepted at this layer but checked upstream. The
// per-RPC bearer-token auth (CheckAuth) is the only line of defence
// present here.
//
// Session guard: compare WTSGetActiveConsoleSessionId() to the umagent's
// own session (ProcessIdToSessionId). If they differ, return
// "input: umagent not in active session" — SendInput would silently fail
// otherwise.

#include <grpcpp/grpcpp.h>
#include <grpcpp/server_context.h>
#include "pry.grpc.pb.h"
#include "grpc_auth.hpp"

#include <windows.h>
#include <wtsapi32.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <string>
#include <unordered_map>
#include <vector>

#include "services_input.hpp"
#include "um_services.hpp"

#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "user32.lib")

namespace um {

namespace {

// Mirror of the auth helper in services_token.cpp (local by design so
// services_input.cpp stays self-contained; the anonymous-namespace copy
// in um_services.cpp is not visible across TUs).
grpc::Status CheckAuthIn(grpc::ServerContext* ctx, const std::string& token) {
    // One shared constant-time implementation (comm/grpc_auth.hpp). The
    // server-wide auth processor is authoritative; this per-handler
    // call is defence in depth.
    return pry::auth::CheckAuth(ctx, token);
}

// Session-guard: SendInput only reaches the user desktop when the caller
// lives in the active console session. umagent is installed as a session-1
// service but a locked / disconnected box may have no active session at all
// (WTSGetActiveConsoleSessionId → 0xFFFFFFFF).
std::string CheckActiveSession() {
    DWORD active = WTSGetActiveConsoleSessionId();
    if (active == 0xFFFFFFFF) {
        return "input: no active console session";
    }
    DWORD own = 0;
    if (!ProcessIdToSessionId(GetCurrentProcessId(), &own)) {
        return "input: ProcessIdToSessionId failed";
    }
    if (active != own) {
        return "input: umagent not in active session";
    }
    return {};
}

// SendInputWorker — one SendInput call per batch keeps the kernel's
// per-event timestamps monotonic, which matters for apps that snapshot
// GetMessagePos / GetMessageTime between events.
struct SendInputWorker {
    std::vector<INPUT> buf;

    void MouseMoveAbs(int x, int y) {
        // SendInput MOUSEEVENTF_ABSOLUTE wants [0, 65535] across the
        // virtual screen. Translate the caller's screen-space pixels
        // against GetSystemMetrics(SM_XVIRTUALSCREEN / CXVIRTUALSCREEN).
        int vx = GetSystemMetrics(SM_XVIRTUALSCREEN);
        int vy = GetSystemMetrics(SM_YVIRTUALSCREEN);
        int vw = GetSystemMetrics(SM_CXVIRTUALSCREEN);
        int vh = GetSystemMetrics(SM_CYVIRTUALSCREEN);
        if (vw <= 0) vw = 1;
        if (vh <= 0) vh = 1;
        LONG nx = static_cast<LONG>((static_cast<LONGLONG>(x - vx) * 65535) / vw);
        LONG ny = static_cast<LONG>((static_cast<LONGLONG>(y - vy) * 65535) / vh);
        INPUT in{};
        in.type = INPUT_MOUSE;
        in.mi.dx = nx;
        in.mi.dy = ny;
        in.mi.dwFlags = MOUSEEVENTF_ABSOLUTE | MOUSEEVENTF_MOVE |
                        MOUSEEVENTF_VIRTUALDESK;
        buf.push_back(in);
    }

    void MouseButton(pry::InputButton button, bool down) {
        INPUT in{};
        in.type = INPUT_MOUSE;
        switch (button) {
            case pry::INPUT_LEFT:
                in.mi.dwFlags = down ? MOUSEEVENTF_LEFTDOWN
                                     : MOUSEEVENTF_LEFTUP;
                break;
            case pry::INPUT_RIGHT:
                in.mi.dwFlags = down ? MOUSEEVENTF_RIGHTDOWN
                                     : MOUSEEVENTF_RIGHTUP;
                break;
            case pry::INPUT_MIDDLE:
                in.mi.dwFlags = down ? MOUSEEVENTF_MIDDLEDOWN
                                     : MOUSEEVENTF_MIDDLEUP;
                break;
            case pry::INPUT_X1:
                in.mi.dwFlags = down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
                in.mi.mouseData = XBUTTON1;
                break;
            case pry::INPUT_X2:
                in.mi.dwFlags = down ? MOUSEEVENTF_XDOWN : MOUSEEVENTF_XUP;
                in.mi.mouseData = XBUTTON2;
                break;
            default:
                return;
        }
        buf.push_back(in);
    }

    void KeyVk(WORD vk, bool down, bool extended = false) {
        INPUT in{};
        in.type = INPUT_KEYBOARD;
        in.ki.wVk = vk;
        in.ki.wScan = static_cast<WORD>(MapVirtualKeyW(vk, MAPVK_VK_TO_VSC));
        in.ki.dwFlags = (down ? 0 : KEYEVENTF_KEYUP) |
                        (extended ? KEYEVENTF_EXTENDEDKEY : 0);
        buf.push_back(in);
    }

    void KeyUnicode(wchar_t ch, bool down) {
        INPUT in{};
        in.type = INPUT_KEYBOARD;
        in.ki.wVk = 0;
        in.ki.wScan = static_cast<WORD>(ch);
        in.ki.dwFlags = KEYEVENTF_UNICODE | (down ? 0 : KEYEVENTF_KEYUP);
        buf.push_back(in);
    }

    // Modifier bitfield: bit 0 = shift, 1 = ctrl, 2 = alt, 3 = win.
    void ModifiersDown(uint32_t modifiers) {
        if (modifiers & 0x01) KeyVk(VK_SHIFT, true);
        if (modifiers & 0x02) KeyVk(VK_CONTROL, true);
        if (modifiers & 0x04) KeyVk(VK_MENU, true);
        if (modifiers & 0x08) KeyVk(VK_LWIN, true);
    }
    void ModifiersUp(uint32_t modifiers) {
        if (modifiers & 0x08) KeyVk(VK_LWIN, false);
        if (modifiers & 0x04) KeyVk(VK_MENU, false);
        if (modifiers & 0x02) KeyVk(VK_CONTROL, false);
        if (modifiers & 0x01) KeyVk(VK_SHIFT, false);
    }

    // Flush the buffer with a single SendInput call. Returns "" on success
    // or a short error string.
    std::string Flush() {
        if (buf.empty()) return {};
        UINT sent = SendInput(static_cast<UINT>(buf.size()),
                              buf.data(), sizeof(INPUT));
        UINT want = static_cast<UINT>(buf.size());
        buf.clear();
        if (sent != want) {
            DWORD err = GetLastError();
            return std::string("input: SendInput partial (") +
                   std::to_string(sent) + "/" + std::to_string(want) +
                   "), gle=" + std::to_string(err);
        }
        return {};
    }
};

// VkFromKeyName — handles both multi-character key names ("Escape", "F5",
// "PageUp") and single ASCII letters / digits. Returns 0 on unknown names.
WORD VkFromKeyName(const std::string& name, bool* extendedOut) {
    *extendedOut = false;
    if (name.empty()) return 0;
    // Normalize to lowercase for the table lookup.
    std::string n;
    n.reserve(name.size());
    for (char c : name) n.push_back(
        static_cast<char>(std::tolower(static_cast<unsigned char>(c))));

    // Fast path for single letters / digits.
    if (n.size() == 1) {
        char c = n[0];
        if (c >= 'a' && c <= 'z') return static_cast<WORD>('A' + (c - 'a'));
        if (c >= '0' && c <= '9') return static_cast<WORD>(c);
    }

    // F1 .. F24.
    if (n.size() >= 2 && n[0] == 'f') {
        bool allDigits = true;
        for (size_t i = 1; i < n.size(); ++i) {
            if (!std::isdigit(static_cast<unsigned char>(n[i]))) {
                allDigits = false;
                break;
            }
        }
        if (allDigits) {
            int num = std::atoi(n.c_str() + 1);
            if (num >= 1 && num <= 24) {
                return static_cast<WORD>(VK_F1 + (num - 1));
            }
        }
    }

    static const std::unordered_map<std::string, std::pair<WORD, bool>> table = {
        {"escape",    {VK_ESCAPE,   false}},
        {"esc",       {VK_ESCAPE,   false}},
        {"enter",     {VK_RETURN,   false}},
        {"return",    {VK_RETURN,   false}},
        {"tab",       {VK_TAB,      false}},
        {"backspace", {VK_BACK,     false}},
        {"bs",        {VK_BACK,     false}},
        {"delete",    {VK_DELETE,   true}},
        {"del",       {VK_DELETE,   true}},
        {"insert",    {VK_INSERT,   true}},
        {"ins",       {VK_INSERT,   true}},
        {"home",      {VK_HOME,     true}},
        {"end",       {VK_END,      true}},
        {"pageup",    {VK_PRIOR,    true}},
        {"pgup",      {VK_PRIOR,    true}},
        {"pagedown",  {VK_NEXT,     true}},
        {"pgdn",      {VK_NEXT,     true}},
        {"up",        {VK_UP,       true}},
        {"down",      {VK_DOWN,     true}},
        {"left",      {VK_LEFT,     true}},
        {"right",     {VK_RIGHT,    true}},
        {"space",     {VK_SPACE,    false}},
        {"capslock",  {VK_CAPITAL,  false}},
        {"numlock",   {VK_NUMLOCK,  false}},
        {"scrolllock",{VK_SCROLL,   false}},
        {"printscreen",{VK_SNAPSHOT,true}},
        {"prtsc",     {VK_SNAPSHOT, true}},
        {"pause",     {VK_PAUSE,    false}},
    };
    auto it = table.find(n);
    if (it != table.end()) {
        *extendedOut = it->second.second;
        return it->second.first;
    }
    return 0;
}

// ParseKeyString — "Ctrl+Shift+F5" → (modifiers, keyVk, extended).
// Returns false if the final token cannot be mapped to a key.
bool ParseKeyString(const std::string& key, uint32_t* modifiers, WORD* vk,
                    bool* extended, std::string* err) {
    *modifiers = 0;
    *vk = 0;
    *extended = false;

    std::vector<std::string> tokens;
    std::string cur;
    for (char c : key) {
        if (c == '+') {
            if (!cur.empty()) tokens.push_back(std::move(cur));
            cur.clear();
        } else {
            cur.push_back(c);
        }
    }
    if (!cur.empty()) tokens.push_back(std::move(cur));

    if (tokens.empty()) {
        *err = "input: empty key string";
        return false;
    }

    // Strip whitespace, lowercase for modifier matching.
    auto lower = [](const std::string& s) {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            if (std::isspace(static_cast<unsigned char>(c))) continue;
            out.push_back(static_cast<char>(
                std::tolower(static_cast<unsigned char>(c))));
        }
        return out;
    };

    for (size_t i = 0; i + 1 < tokens.size(); ++i) {
        std::string m = lower(tokens[i]);
        if (m == "ctrl" || m == "control") *modifiers |= 0x02;
        else if (m == "shift")             *modifiers |= 0x01;
        else if (m == "alt" || m == "menu") *modifiers |= 0x04;
        else if (m == "win" || m == "super" || m == "meta") *modifiers |= 0x08;
        else {
            *err = "input: unknown modifier '" + tokens[i] + "'";
            return false;
        }
    }

    const std::string& keyTok = tokens.back();
    WORD k = VkFromKeyName(keyTok, extended);
    if (k == 0) {
        *err = "input: unknown key '" + keyTok + "'";
        return false;
    }
    *vk = k;
    return true;
}

// Utf8ToUtf16 — proto strings are UTF-8; Windows input needs UTF-16.
std::wstring Utf8ToUtf16(const std::string& s) {
    if (s.empty()) return {};
    int n = MultiByteToWideChar(CP_UTF8, 0, s.data(),
                                static_cast<int>(s.size()), nullptr, 0);
    if (n <= 0) return {};
    std::wstring out;
    out.resize(static_cast<size_t>(n));
    MultiByteToWideChar(CP_UTF8, 0, s.data(), static_cast<int>(s.size()),
                        out.data(), n);
    return out;
}

class UmInputSvc final : public pry::Input::Service {
public:
    explicit UmInputSvc(const Config& cfg) : cfg_(cfg) {}

    grpc::Status Click(grpc::ServerContext* ctx,
                       const pry::InputClickRequest* req,
                       pry::InputResponse* resp) override {
        auto auth = CheckAuthIn(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        std::string sessErr = CheckActiveSession();
        if (!sessErr.empty()) {
            FillStatus(resp, sessErr);
            return grpc::Status::OK;
        }

        SendInputWorker w;
        uint32_t mods = req->modifiers();
        if (mods) w.ModifiersDown(mods);

        // -1 / -1 means "operate on the current cursor" per the proto doc.
        if (req->x() >= 0 && req->y() >= 0) {
            w.MouseMoveAbs(req->x(), req->y());
        }

        uint32_t count = req->click_count();
        if (count == 0) count = 1;
        if (count > 8) count = 8;  // defensive cap; SendInput cost is linear

        pry::InputAction act = req->action();
        for (uint32_t i = 0; i < count; ++i) {
            if (act == pry::INPUT_DOWN) {
                w.MouseButton(req->button(), true);
            } else if (act == pry::INPUT_UP) {
                w.MouseButton(req->button(), false);
            } else {  // INPUT_CLICK
                w.MouseButton(req->button(), true);
                w.MouseButton(req->button(), false);
            }
        }

        if (mods) w.ModifiersUp(mods);

        std::string err = w.Flush();
        FillStatus(resp, err);
        return grpc::Status::OK;
    }

    grpc::Status Type(grpc::ServerContext* ctx,
                      const pry::InputTypeRequest* req,
                      pry::InputResponse* resp) override {
        auto auth = CheckAuthIn(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        std::string sessErr = CheckActiveSession();
        if (!sessErr.empty()) {
            FillStatus(resp, sessErr);
            return grpc::Status::OK;
        }

        std::wstring text = Utf8ToUtf16(req->text());
        uint32_t delay = req->delay_ms();

        // Each code point is flushed separately when delay_ms > 0 so the
        // Sleep interleaves correctly; otherwise we batch the whole string
        // into one SendInput call.
        if (delay == 0) {
            SendInputWorker w;
            for (wchar_t ch : text) {
                SHORT vks = VkKeyScanW(ch);
                if (vks == -1) {
                    w.KeyUnicode(ch, true);
                    w.KeyUnicode(ch, false);
                    continue;
                }
                WORD vk = static_cast<WORD>(vks & 0xFF);
                BYTE mods = static_cast<BYTE>((vks >> 8) & 0xFF);
                bool shift = (mods & 1) != 0;
                bool ctrl  = (mods & 2) != 0;
                bool alt   = (mods & 4) != 0;
                if (shift) w.KeyVk(VK_SHIFT, true);
                if (ctrl)  w.KeyVk(VK_CONTROL, true);
                if (alt)   w.KeyVk(VK_MENU, true);
                w.KeyVk(vk, true);
                w.KeyVk(vk, false);
                if (alt)   w.KeyVk(VK_MENU, false);
                if (ctrl)  w.KeyVk(VK_CONTROL, false);
                if (shift) w.KeyVk(VK_SHIFT, false);
            }
            FillStatus(resp, w.Flush());
            return grpc::Status::OK;
        }

        for (size_t i = 0; i < text.size(); ++i) {
            SendInputWorker w;
            wchar_t ch = text[i];
            SHORT vks = VkKeyScanW(ch);
            if (vks == -1) {
                w.KeyUnicode(ch, true);
                w.KeyUnicode(ch, false);
            } else {
                WORD vk = static_cast<WORD>(vks & 0xFF);
                BYTE mods = static_cast<BYTE>((vks >> 8) & 0xFF);
                bool shift = (mods & 1) != 0;
                bool ctrl  = (mods & 2) != 0;
                bool alt   = (mods & 4) != 0;
                if (shift) w.KeyVk(VK_SHIFT, true);
                if (ctrl)  w.KeyVk(VK_CONTROL, true);
                if (alt)   w.KeyVk(VK_MENU, true);
                w.KeyVk(vk, true);
                w.KeyVk(vk, false);
                if (alt)   w.KeyVk(VK_MENU, false);
                if (ctrl)  w.KeyVk(VK_CONTROL, false);
                if (shift) w.KeyVk(VK_SHIFT, false);
            }
            std::string err = w.Flush();
            if (!err.empty()) {
                FillStatus(resp, err);
                return grpc::Status::OK;
            }
            if (i + 1 < text.size()) Sleep(delay);
        }

        FillStatus(resp, std::string{});
        return grpc::Status::OK;
    }

    grpc::Status Key(grpc::ServerContext* ctx,
                     const pry::InputKeyRequest* req,
                     pry::InputResponse* resp) override {
        auto auth = CheckAuthIn(ctx, cfg_.token);
        if (!auth.ok()) return auth;

        std::string sessErr = CheckActiveSession();
        if (!sessErr.empty()) {
            FillStatus(resp, sessErr);
            return grpc::Status::OK;
        }

        uint32_t mods = 0;
        WORD vk = 0;
        bool extended = false;
        std::string err;
        if (!ParseKeyString(req->key(), &mods, &vk, &extended, &err)) {
            FillStatus(resp, err);
            return grpc::Status::OK;
        }

        uint32_t repeat = req->repeat();
        if (repeat == 0) repeat = 1;
        if (repeat > 1024) repeat = 1024;  // defensive cap

        SendInputWorker w;
        pry::InputAction act = req->action();
        for (uint32_t i = 0; i < repeat; ++i) {
            if (mods) w.ModifiersDown(mods);
            if (act == pry::INPUT_DOWN) {
                w.KeyVk(vk, true, extended);
            } else if (act == pry::INPUT_UP) {
                w.KeyVk(vk, false, extended);
            } else {  // INPUT_CLICK
                w.KeyVk(vk, true, extended);
                w.KeyVk(vk, false, extended);
            }
            if (mods) w.ModifiersUp(mods);
        }

        FillStatus(resp, w.Flush());
        return grpc::Status::OK;
    }

private:
    const Config& cfg_;
};

}  // namespace

void RegisterInputService(grpc::ServerBuilder& builder, const Config& cfg) {
    static UmInputSvc svc(cfg);
    builder.RegisterService(&svc);
}

}  // namespace um
