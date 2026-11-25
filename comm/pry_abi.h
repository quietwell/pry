#ifndef PRY_ABI_H
#define PRY_ABI_H

// Wire ABI shared by pry_driver.sys (kernel, C), comm/ (user, C++) and
// tools/drv_exerciser. Fixed-layout, no pointers, no C++. Any change here
// is a breaking ABI change: bump PRY_ABI_VERSION and the driver epoch.
//
// This header is a thin aggregator — the real content lives under
// `comm/abi/*.h`, split by subsystem (R1 restructuring). Every existing
// `#include "pry_abi.h"` keeps working through this shim; each
// subheader is also independently includeable (it carries its own OS
// header include and extern "C" guard).

#include "abi/version.h"
#include "abi/mem.h"
#include "abi/proc.h"
#include "abi/bp.h"
#include "abi/call.h"
#include "abi/notify.h"
#include "abi/watchdog.h"

/* ---- SI adoption landing stubs (R0 scaffolding) ---- */
#include "abi/comm_port.h"
#include "abi/informer.h"
#include "abi/token.h"
#include "abi/dyn.h"

#endif // PRY_ABI_H
