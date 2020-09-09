#include "BufferPool.h"

BufferPool *BufferPool::buffer_pool = NULL;

std::mutex _buffer_mutex;

crust::Log *p_log = crust::Log::get_instance();

/**
 * @description: Get single instance
 * @return: Single instance
 */
BufferPool *BufferPool::get_instance()
{
    if (BufferPool::buffer_pool == NULL)
    {
        BufferPool::buffer_pool = new BufferPool();
    }

    return BufferPool::buffer_pool;
}

/**
 * @description: Allocate buffers
 */
BufferPool::BufferPool()
{
    for (uint32_t i = 0; i < this->_buffer_num; i++)
    {
        uint8_t *buf = (uint8_t*)malloc(_buffer_size);
        if (buf == NULL)
        {
            p_log->err("Allocate persist buffer(num:%d) failed!", i);
            continue;
        }
        memset(buf, 0, _buffer_size);
        memcpy(buf, BUFFER_AVAILABLE, strlen(BUFFER_AVAILABLE));
        this->buffers.push_back(std::make_pair(buf, _buffer_size));
    }
}

/**
 * @description: Free buffers
 */
BufferPool::~BufferPool()
{
    for (uint32_t i = 0; i < this->buffers.size(); i++)
    {
        if (this->buffers[i].first != NULL)
        {
            free(this->buffers[i].first);
        }
    }
}

/**
 * @description: Get available buffer
 * @param buf_len -> Indicated buffer length
 * @return: Poniter to available buffer
 */
uint8_t *BufferPool::get_buffer(size_t buf_len)
{
    _buffer_mutex.lock();
    int tryout = 300;
    // Get available buffer
    do
    {
        if (cur_index >= this->buffers.size())
        {
            cur_index = cur_index % this->buffers.size();
        }
        if (memcmp(this->buffers[cur_index].first, BUFFER_AVAILABLE, strlen(BUFFER_AVAILABLE)) == 0)
        {
            break;
        }
        cur_index++;
        usleep(100000);
    } while (tryout-- > 0);
    // Check if buffer is enough
    if (buf_len > this->buffers[cur_index].second)
    {
        free(this->buffers[cur_index].first);
        this->buffers[cur_index].first = (uint8_t*)malloc(buf_len);
        this->buffers[cur_index].second = buf_len;
        memset(this->buffers[cur_index].first, 0, buf_len);
    }
    else
    {
        memset(this->buffers[cur_index].first, 0, this->buffers[cur_index].second);
    }
    _buffer_mutex.unlock();
    return this->buffers[cur_index].first;
}
