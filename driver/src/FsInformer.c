#include "PryDriver.h"

// FsInformer.c — SI adoption feature #22: minifilter FS pre-op callbacks.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 3 PR; see
// an internal plan feature 22.
// Will host pre-op callbacks for IRP_MJ_CREATE, _WRITE, _SET_INFORMATION
// and _CLEANUP, plus FltGetFileNameInformation path extraction, the
// path-prefix / PID allow-deny filter, and the per-category rate-limit
// token bucket. Events feed the same PRY_EVT ring Notify.c owns.
