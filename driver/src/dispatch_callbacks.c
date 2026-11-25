#include "PryDriver.h"

// dispatch_callbacks.c — SI adoption feature #5: dispatcher glue for
// PRY_IOCTL_CALLBACKS_ENUM and PRY_IOCTL_CALLBACKS_RESOLVER_STATS.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 2 PR; see
// an internal plan feature 5.
// Mirrors dispatch_notify.c:PryHandleObjEnum (METHOD_OUT_DIRECT with
// a trailing modules table).
