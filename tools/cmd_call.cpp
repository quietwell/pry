// drv_exerciser kcall — synchronous kernel function call (ABI v13).
#include "exerciser_common.hpp"

using namespace pry;

int CmdKcall(UINT64 target, const std::vector<UINT64>& args, UINT32 timeoutMs, bool force)
{
    PRY_KERNEL_CALL_IN in = {};
    PRY_KERNEL_CALL_OUT out = {};
    in.Target = target;
    in.Argc = (UINT32)args.size();
    if (in.Argc > PRY_KC_MAX_ARGS) {
        printf("FAIL kcall: argc=%u > %d\n", (unsigned)in.Argc, PRY_KC_MAX_ARGS);
        return 1;
    }
    for (size_t i = 0; i < args.size(); ++i) {
        in.Args[i] = args[i];
    }
    in.TimeoutMs = timeoutMs;
    in.Flags = force ? PRY_KC_FLAG_FORCE : 0;
    if (!g_drv.KernelCall(in, &out)) {
        printf("FAIL kcall: %s\n", g_drv.LastError().c_str());
        return 1;
    }
    printf("PASS kcall st=%x done=%u ex=%u excode=%x ret=%llx\n",
           (unsigned)out.Status, (unsigned)out.Completed, (unsigned)out.Exception,
           (unsigned)out.ExceptionCode, (unsigned long long)out.ReturnValue);
    return 0;
}