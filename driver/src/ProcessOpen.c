#include "PryDriver.h"

// ProcessOpen.c — SI adoption feature #23: protected-process open via KernelMode.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 1 PR; see
// an internal plan feature 4.
// Will host PryOpenProcessKm() and PryOpenThreadKm() using the
// ObOpenObjectByPointer(KernelMode) pattern Threads.c already uses for
// transient enrichment handles. Dispatch wiring extends dispatch_proc.c.
