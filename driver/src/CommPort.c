#include "PryDriver.h"

// CommPort.c — SI adoption feature #20: minifilter comm port push channel.
//
// Landing spot (R0 scaffolding). Populated by the SI Wave 3 PR; see
// an internal plan feature 20.
// Will host FltRegisterFilter + FltCreateCommunicationPort (empty
// Callbacks[] in #20 — feature #22 adds pre-op FS/REG callbacks to the
// same registration), the per-client PFLT_PORT list, and the PASSIVE
// drain worker that pumps PRY_EVT records out via FltSendMessage.
