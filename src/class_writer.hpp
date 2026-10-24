#pragma once
#include <cstring>
#include <cstdint>
#include <algorithm>
#include <cstdio>
#include <unistd.h>
#include "../aethon/aethon.h"

#ifndef FLUXIO_H_GUARD_
#define FLUXIO_H_GUARD_
#define FLUXIO_ALWAYS_INLINE AETHON_ALWAYS_INLINE
#define FLUXIO_SAFE_CHECK AETHON_SAFE_CHECK
#define FLUXIO_UNLIKELY AETHON_UNLIKELY
#define FLUXIO_LIKELY AETHON_LIKELY
#define FLUXIO_BUILTIN_PREFETCH AETHON_BUILTIN_PREFETCH
#define FLUXIO_PAUSE_CPU_INSTRUCTION AETHON_PAUSE_CPU_INSTRUCTION
#define FLUXIO_ATTR_GNU_COLD AETHON_ATTR_GNU_COLD
namespace flux {
    namespace Trait = ::Trait;
    namespace variableTemplates = ::variableTemplates;
    namespace implementation = ::implementation;
}
#endif
#include <fluxio.h>
#define MAX_FILE_NAME_SIZE 100

class BatchWriter {
private:
    char filename[MAX_FILE_NAME_SIZE]{};
    flux::flux_storage_engine<4, 32, 4096> engine;

public:
    BatchWriter(const char* file, int slot = 0) {
        if (!file) return;
        std::snprintf(filename, sizeof(filename), "%s", file);
        if (!engine.register_file(slot, filename)) {
            AETHON_SAFE_CHECK(false, "Failed to register file\n");
        }
        if (!engine.setup_io_uring()) {
            AETHON_SAFE_CHECK(false, "Failed to setup io_uring backend\n");
        }
    }

    AETHON_ALWAYS_INLINE int write_data(const char* data, int size, int slot, int* offset) {
        if (!data || size <= 0 || !offset)  return -1;
        constexpr uint32_t page_sz = 4096;
        constexpr uint32_t q_depth = 32; 
        const uint32_t num_chunks = (static_cast<uint32_t>(size)+page_sz-1)/page_sz;
        uint32_t submitted = 0;
        uint32_t completed = 0;
        bool success = true;
        char partial_buf[page_sz]{};

        while (completed < num_chunks) {
            while (submitted < num_chunks && (submitted - completed) < q_depth) {
                uint32_t data_pos = submitted * page_sz;
                uint32_t chunk_len = std::min(static_cast<uint32_t>(size)-data_pos,page_sz);
                uint64_t file_off = static_cast<uint64_t>(*offset)+data_pos;
                const void* src = nullptr;
                uint32_t req_len = chunk_len;

                if (chunk_len < page_sz) {
                    std::memset(partial_buf, 0, page_sz);
                    std::memcpy(partial_buf, data + data_pos, chunk_len);
                    src = partial_buf;
                    req_len = page_sz;
                } else src = data + data_pos;

                flux::IORequest req{};
                req.op_type = flux::Type::Write;
                req.file_slot = static_cast<uint16_t>(slot);
                req.length = req_len;
                req.file_offset = file_off;
                req.user_data = submitted;
                req.data_src = src;
                engine.push_request(std::move(req));
                submitted++;
            }
            engine.process_submissions();
            engine.poll_completion();
            flux::IoCompletion comp{};
            while (engine.try_pop_completion(comp)) {
                if (AETHON_UNLIKELY(comp.failed)) {
                    success = false;
                }
                completed++;
            }
        }
        int final_offset = *offset + size;
        *offset = final_offset;
        if (success) {
            int fd = engine.get_fd(slot);
            if (fd >= 0) {
                ::ftruncate(fd, final_offset);
            }
        }
        return success ? 0 : -1;
    }
};