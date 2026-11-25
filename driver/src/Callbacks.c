#include "PryDriver.h"

// Callbacks.c — SI adoption feature #5: kernel callback enumeration.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 2 PR; see
// an internal plan feature 5.
// Will host PryCallbacksEnum() plus one static per-class walker
// (process-create, image-load, thread-create, registry, object,
// minifilter, shutdown, bugcheck) and the PryCallbacksInit /
// PryCallbacksShutdown entry points called from DriverEntry.
