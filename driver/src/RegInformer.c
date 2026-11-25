#include "PryDriver.h"

// RegInformer.c — SI adoption feature #22: registry callback informer.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 3 PR; see
// an internal plan feature 22.
// Will host CmRegisterCallbackEx (altitude "370000") and the per-op
// handlers that emit PRY_EVT_KIND_REG_* records into the shared ring
// under the same self-filter + rate-limit discipline FsInformer.c uses.
