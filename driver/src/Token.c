#include "PryDriver.h"

// Token.c — SI adoption feature #24: session-token privilege model.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 3 PR; see
// an internal plan feature 24.
// Will host PryTokenRegister() / PryTokenRevoke() / PryTokenCheck()
// over a 32-slot table, the 128-entry rolling nonce replay guard, the
// caller-image SHA256 bind, and the per-IoControlCode -> required-priv
// policy switch Dispatcher.c calls before each gated verb. Reuses the
// BCrypt handle and pinned RSA key from Dyn.c (feature #19).
