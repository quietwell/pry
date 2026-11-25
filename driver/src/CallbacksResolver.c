#include "PryDriver.h"

// CallbacksResolver.c — SI adoption feature #5: array-base resolver for
// kernel callback enumeration.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 2 PR; see
// an internal plan feature 5.
// Will host the ntoskrnl prolog pattern-scan ("lea rcx, [rip+disp32]")
// that locates PspCreateProcessNotifyRoutine, CmpCallbackListHead,
// IopNotifyShutdownQueueHead, KeBugCheckCallbackListHead, and the
// OBJECT_TYPE.CallbackList offset probe. Falls back to the #19 dyn-data
// table when present.
