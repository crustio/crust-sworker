#ifndef _BUFFER_POOL_H_
#define _BUFFER_POOL_H_

#include <stdio.h>
#include <mutex>
#include <vector>
#include <string.h>
#include <utility>

class BufferPool
{

public:
    static BufferPool *get_instance();
    static BufferPool *buffer_pool;
    uint8_t *get_buffer(size_t buf_len);
    ~BufferPool();

private:
    BufferPool();
    uint32_t cur_index = 0;
    std::vector<std::pair<uint8_t*, size_t>> buffers;
    size_t _buffer_size = 2*1024*1024;
    uint32_t _buffer_num = 5;

};

#endif /* !_BUFFER_POOL_H_ */
