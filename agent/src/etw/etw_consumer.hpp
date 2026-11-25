#pragma once
// agent/src/etw/etw_consumer.hpp — SI #10 ETW consumer + SPSC ring.
//
// Lock-free single-producer / single-consumer ring: the ETW
// EventRecordCallback (producer) runs on ProcessTrace's dedicated
// worker thread, Tail / Events RPCs (consumer) drain from the gRPC
// thread. The ring overwrites oldest on overflow — same semantics as
// the driver notify ring — and the orchestrator sees drops as a
// monotonically-growing counter in Stats.
//
// All event decoding (TdhGetEventInformation + TdhGetProperty) runs on
// the producer thread so the Python side never pays the per-event
// cost. See an internal plan
// §Feature 8 (Wave 1 note: TDH on C++ side to avoid GIL pressure).

#include <atomic>
#include <cstdint>
#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

namespace pry::etw {

struct EtwEvent {
    uint64_t seq = 0;
    uint64_t ts_100ns = 0;
    std::string provider_guid;
    uint32_t event_id = 0;
    uint32_t pid = 0;
    uint32_t tid = 0;
    uint32_t opcode = 0;
    uint32_t version = 0;
    uint32_t level = 0;
    uint64_t keywords = 0;
    std::string kind;
    std::map<std::string, std::string> fields;
};

// Power-of-two capacity SPSC ring, overwrite-oldest. The producer
// never blocks; the consumer sees a monotonic drop counter.
class SpscRing {
public:
    explicit SpscRing(uint32_t capacity);

    uint32_t capacity() const { return cap_; }
    uint64_t dropped() const { return dropped_.load(std::memory_order_relaxed); }
    uint64_t total() const { return total_.load(std::memory_order_relaxed); }
    uint32_t used() const;

    // Producer side (ETW callback thread). Never blocks.
    void Push(EtwEvent evt);

    // Consumer side (gRPC thread).
    // Drains at most `limit` events (0 => up to capacity), skipping any
    // whose seq <= since_seq. Returns the drained vector plus the
    // highest seq observed (0 if the ring was empty).
    std::vector<EtwEvent> Drain(uint32_t limit, uint64_t since_seq,
                                 uint64_t* out_last_seq);

private:
    uint32_t cap_;
    uint32_t mask_;
    std::unique_ptr<EtwEvent[]> slots_;
    std::atomic<uint64_t> head_{0};  // producer writes head_+1
    std::atomic<uint64_t> tail_{0};  // consumer reads tail_
    std::atomic<uint64_t> dropped_{0};
    std::atomic<uint64_t> total_{0};
    std::atomic<uint64_t> seq_{0};
    // Drain is the only mutator of tail_; the consumer side guards it
    // so parallel RPCs on the same session don't race each other.
    std::mutex drain_lock_;
};

class EtwSession;

// Consumer thread wrapper. Runs OpenTrace + ProcessTrace on its own
// worker thread; the ETW EventRecordCallback decodes via TDH and
// pushes a row into `ring_`.
class EtwConsumer {
public:
    EtwConsumer();
    ~EtwConsumer();

    // Starts the ProcessTrace thread against the already-started
    // session. The consumer records back-pointers to its session so
    // the EventRecordCallback can bump counters and the EOF path can
    // signal Stop().
    bool Start(EtwSession* session, uint32_t ring_capacity,
                std::string* err);

    // Signals ProcessTrace to exit (ControlTrace STOP) and joins the
    // worker thread. Idempotent.
    void Stop();

    bool running() const { return running_.load(std::memory_order_acquire); }

    SpscRing& ring() { return *ring_; }

    uint64_t events_lost() const {
        return events_lost_.load(std::memory_order_relaxed);
    }
    uint64_t buffers_written() const {
        return buffers_written_.load(std::memory_order_relaxed);
    }
    uint64_t buffers_lost() const {
        return buffers_lost_.load(std::memory_order_relaxed);
    }

    // Called from the ETW callback (static trampoline below).
    void OnEvent(const void* record);
    void OnBuffer(const void* logfile);

private:
    std::unique_ptr<SpscRing> ring_;
    EtwSession* session_ = nullptr;
    std::thread worker_;
    std::atomic<bool> running_{false};
    std::atomic<bool> stopping_{false};
    uint64_t trace_handle_ = 0;  // TRACEHANDLE (0xFFFFFFFFFFFFFFFF == invalid)
    std::atomic<uint64_t> events_lost_{0};
    std::atomic<uint64_t> buffers_written_{0};
    std::atomic<uint64_t> buffers_lost_{0};
};

}  // namespace pry::etw
