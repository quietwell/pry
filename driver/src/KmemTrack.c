#include "PryDriver.h"

typedef struct _PRY_KALLOC_REC {
    struct _PRY_KALLOC_REC* Next;
    UINT64 Address;
    UINT64 Size;
} PRY_KALLOC_REC, *PPRY_KALLOC_REC;

static PPRY_KALLOC_REC PryKAllocHead;
static KSPIN_LOCK PryKAllocLock;
static volatile LONG PryKAllocReady = 0;

VOID PryKmemInit(VOID)
{
    KeInitializeSpinLock(&PryKAllocLock);
    PryKAllocHead = NULL;
    InterlockedExchange(&PryKAllocReady, 1);
}

NTSTATUS PryKmemAlloc(_In_ UINT64 Size, _Out_ UINT64* Address)
{
    PVOID p;
    PPRY_KALLOC_REC rec;
    KIRQL irql;

    *Address = 0;
    if (!Size || Size > (256ull * 1024 * 1024)) {
        return STATUS_INVALID_PARAMETER;
    }
    if (!InterlockedCompareExchange(&PryKAllocReady, 1, 1)) {
        return STATUS_DEVICE_NOT_READY;
    }
    p = PryAlloc((SIZE_T)Size);
    if (!p) {
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    rec = (PPRY_KALLOC_REC)PryAlloc(sizeof(*rec));
    if (!rec) {
        PryFree(p);
        return STATUS_INSUFFICIENT_RESOURCES;
    }
    rec->Address = (UINT64)(ULONG_PTR)p;
    rec->Size = Size;
    KeAcquireSpinLock(&PryKAllocLock, &irql);
    rec->Next = PryKAllocHead;
    PryKAllocHead = rec;
    KeReleaseSpinLock(&PryKAllocLock, irql);
    *Address = rec->Address;
    return STATUS_SUCCESS;
}

NTSTATUS PryKmemFree(_In_ UINT64 Address)
{
    PPRY_KALLOC_REC prev = NULL, cur;
    KIRQL irql;

    if (!Address) {
        return STATUS_INVALID_PARAMETER;
    }
    KeAcquireSpinLock(&PryKAllocLock, &irql);
    cur = PryKAllocHead;
    while (cur) {
        if (cur->Address == Address) {
            if (prev) {
                prev->Next = cur->Next;
            } else {
                PryKAllocHead = cur->Next;
            }
            KeReleaseSpinLock(&PryKAllocLock, irql);
            PryFree((PVOID)(ULONG_PTR)cur->Address);
            PryFree(cur);
            return STATUS_SUCCESS;
        }
        prev = cur;
        cur = cur->Next;
    }
    KeReleaseSpinLock(&PryKAllocLock, irql);
    // refusing to free untracked pool: only addresses from KMEM_ALLOC
    PryLog("KFREE refused untracked addr=%llx", Address);
    return STATUS_INVALID_PARAMETER;
}

// number of live tracked KMEM_ALLOC blocks (unload-time visibility: mapped
// images intentionally stay allocated; the count in the unload log is the
// lab operator's hint that pool is still in use)
ULONG PryKmemLeakCount(VOID)
{
    PPRY_KALLOC_REC cur;
    KIRQL irql;
    ULONG n = 0;

    KeAcquireSpinLock(&PryKAllocLock, &irql);
    for (cur = PryKAllocHead; cur; cur = cur->Next) {
        n++;
    }
    KeReleaseSpinLock(&PryKAllocLock, irql);
    return n;
}

// unload-time teardown. Every block still tracked
// here has outlived any caller that could still hold its address -- the
// control device is already gone by the time EvtDriverUnload runs this
// -- so free the pool block and its tracking record for each, and refuse
// any further KMEM_ALLOC (mirrors the pre-init PryKAllocReady gate).
ULONG PryKmemFreeAll(VOID)
{
    PPRY_KALLOC_REC cur;
    KIRQL irql;
    ULONG n = 0;

    KeAcquireSpinLock(&PryKAllocLock, &irql);
    InterlockedExchange(&PryKAllocReady, 0);
    cur = PryKAllocHead;
    PryKAllocHead = NULL;
    KeReleaseSpinLock(&PryKAllocLock, irql);

    while (cur) {
        PPRY_KALLOC_REC next = cur->Next;
        PryFree((PVOID)(ULONG_PTR)cur->Address);
        PryFree(cur);
        cur = next;
        n++;
    }
    return n;
}
