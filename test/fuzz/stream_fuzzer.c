/* stream_fuzzer.c - Fuzz the buffered and memory stream layers
 *
 * Exercises mz_stream_buffered and mz_stream_mem directly, covering:
 *   - Buffered read with various sizes (including larger-than-buffer)
 *   - Buffered seek: MZ_SEEK_SET, MZ_SEEK_CUR, MZ_SEEK_END with various offsets
 *     (including negative and out-of-range values)
 *   - Buffered write followed by read-back
 *   - mz_stream_mem_get_buffer_at at various positions (including end-of-buffer)
 *   - mz_stream_mem_set_size (shrink, grow, same size)
 *   - Interleaved read/seek/write sequences driven entirely by fuzz input
 *
 * Input layout:
 *   [n_ops: 1 byte] [ops: n_ops * 4 bytes] [stream_data: remaining bytes]
 *
 *   Each op is 4 bytes:
 *     byte 0: op_type (0=read, 1=seek_cur, 2=seek_set, 3=seek_end,
 *                      4=write, 5=get_buffer_at, 6=set_size, 7=tell)
 *     bytes 1-3: little-endian 24-bit parameter (size / offset)
 */

#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "mz.h"
#include "mz_strm.h"
#include "mz_strm_mem.h"
#include "mz_strm_buf.h"

#define MAX_OPS       64
#define MAX_OP_SIZE   8192
#define READ_BUF_SIZE 4096

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    void *mem_stream = NULL;
    void *buf_stream = NULL;
    uint8_t read_buf[READ_BUF_SIZE];
    const void *ptr = NULL;
    int32_t err;
    uint8_t n_ops;
    const uint8_t *ops;
    const uint8_t *stream_data;
    size_t stream_size;
    int i;

    if (size < 1)
        return 0;

    n_ops = data[0];
    if (n_ops > MAX_OPS)
        n_ops = MAX_OPS;

    /* Need at least 1 byte for n_ops + n_ops*4 for op descriptors */
    if (size < (size_t)(1 + n_ops * 4))
        return 0;

    ops = data + 1;
    stream_data = data + 1 + n_ops * 4;
    stream_size = size - 1 - n_ops * 4;

    /* ---- Memory stream: fuzz get_buffer_at and set_size ---- */
    mem_stream = mz_stream_mem_create();
    if (!mem_stream)
        return 0;

    err = mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE);
    if (err == MZ_OK && stream_size > 0) {
        mz_stream_mem_write(mem_stream, stream_data, (int32_t)stream_size);

        /* Re-open for reading */
        mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_READ);

        /* get_buffer_at at various positions including boundaries */
        if (stream_size > 0) {
            mz_stream_mem_get_buffer_at(mem_stream, 0, &ptr);
            mz_stream_mem_get_buffer_at(mem_stream, (int32_t)stream_size / 2, &ptr);
            mz_stream_mem_get_buffer_at(mem_stream, (int32_t)stream_size - 1, &ptr);
            /* at exactly size (off-by-one boundary — M13 bug) */
            mz_stream_mem_get_buffer_at(mem_stream, (int32_t)stream_size, &ptr);
        }
    }
    mz_stream_mem_delete(&mem_stream);

    /* ---- Memory stream with set_size shrink (C5 bug path) ---- */
    mem_stream = mz_stream_mem_create();
    if (!mem_stream)
        return 0;

    err = mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE);
    if (err == MZ_OK && stream_size > 0) {
        /* Write up to 2*grow_size (8192) bytes to trigger grow */
        int32_t write_len = (int32_t)stream_size;
        if (write_len > 8192) write_len = 8192;
        mz_stream_mem_write(mem_stream, stream_data, write_len);

        /* Re-open CREATE: set_size(grow_size=4096) but buffer is larger — C5 path */
        mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE);
    }
    mz_stream_mem_delete(&mem_stream);

    /* ---- Buffered stream: op-driven read/seek/write ---- */
    mem_stream = mz_stream_mem_create();
    if (!mem_stream)
        return 0;

    /* Use stream_data as read-only backing */
    if (stream_size > 0) {
        mz_stream_mem_set_buffer(mem_stream, (void *)stream_data, (int32_t)stream_size);
        err = mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_READ);
    } else {
        err = mz_stream_mem_open(mem_stream, NULL, MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE);
    }

    if (err != MZ_OK) {
        mz_stream_mem_delete(&mem_stream);
        return 0;
    }

    buf_stream = mz_stream_buffered_create();
    if (!buf_stream) {
        mz_stream_mem_delete(&mem_stream);
        return 0;
    }

    mz_stream_set_base(buf_stream, mem_stream);
    err = mz_stream_buffered_open(buf_stream, NULL,
                                  stream_size > 0 ? MZ_OPEN_MODE_READ
                                                  : MZ_OPEN_MODE_CREATE | MZ_OPEN_MODE_WRITE);
    if (err != MZ_OK) {
        mz_stream_buffered_delete(&buf_stream);
        mz_stream_mem_delete(&mem_stream);
        return 0;
    }

    /* Execute fuzz-driven operations */
    for (i = 0; i < n_ops; i++) {
        uint8_t op_type = ops[i * 4 + 0];
        int32_t param   = (int32_t)((uint32_t)ops[i * 4 + 1]
                        | ((uint32_t)ops[i * 4 + 2] << 8)
                        | ((uint32_t)ops[i * 4 + 3] << 16));
        /* Sign-extend from 24 bits */
        if (param & 0x800000)
            param |= (int32_t)0xFF000000;

        int32_t clamped_size = param < 0 ? -param : param;
        if (clamped_size > READ_BUF_SIZE)
            clamped_size = READ_BUF_SIZE;

        switch (op_type & 0x07) {
        case 0: /* read */
            mz_stream_buffered_read(buf_stream, read_buf, clamped_size);
            break;
        case 1: /* seek CUR */
            mz_stream_buffered_seek(buf_stream, (int64_t)param, MZ_SEEK_CUR);
            break;
        case 2: /* seek SET */
            mz_stream_buffered_seek(buf_stream, (int64_t)(param & 0x7FFFFF), MZ_SEEK_SET);
            break;
        case 3: /* seek END */
            mz_stream_buffered_seek(buf_stream, (int64_t)param, MZ_SEEK_END);
            break;
        case 4: /* write (only if writable) */
            if (stream_size == 0)
                mz_stream_buffered_write(buf_stream, read_buf, clamped_size);
            break;
        case 5: /* tell */
            mz_stream_buffered_tell(buf_stream);
            break;
        case 6: /* read large (> buffer size, exercises refill) */
            mz_stream_buffered_read(buf_stream, read_buf, READ_BUF_SIZE);
            break;
        case 7: /* seek back by 1, then read */
            mz_stream_buffered_seek(buf_stream, -1, MZ_SEEK_CUR);
            mz_stream_buffered_read(buf_stream, read_buf, 1);
            break;
        }
    }

    mz_stream_buffered_close(buf_stream);
    mz_stream_buffered_delete(&buf_stream);
    mz_stream_mem_delete(&mem_stream);

    return 0;
}

/* Standalone driver: read files from argv and call fuzzer */
#ifdef STANDALONE
#include <stdio.h>
int main(int argc, char **argv) {
    FILE *f;
    uint8_t *buf;
    long fsize;
    int i;
    for (i = 1; i < argc; i++) {
        f = fopen(argv[i], "rb");
        if (!f) continue;
        fseek(f, 0, SEEK_END); fsize = ftell(f); fseek(f, 0, SEEK_SET);
        buf = malloc(fsize);
        if (buf) {
            fread(buf, 1, fsize, f);
            LLVMFuzzerTestOneInput(buf, fsize);
            free(buf);
        }
        fclose(f);
    }
    return 0;
}
#endif
