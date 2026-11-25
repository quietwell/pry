#include "PryDriver.h"

// Dyn.c — SI adoption feature #19: signed dynamic-offset blob (dyn-data).
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 3 PR; see
// an internal plan feature 19.
// Will host PryDynInit() (BCrypt provider + pinned RSA pub-key import
// from DynPub.inc), PryDynLoad() (BCryptVerifySignature + atomic swap
// under KSPIN_LOCK), and the PRY_DYN_STATE singleton read by the
// DynEp*() / DynEt*() inline accessors declared in PryDriver.h.
