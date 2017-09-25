#ifndef __PRQUEUE_H
#define __PRQUEUE_H

#ifdef __cplusplus
extern "C"
{
#endif

#include <stdint.h>
#include <stdbool.h>
#include <string.h>

// 10x256 = 2560 = 2.5kb
#define MAX_Q_SIZE 10
#define MAX_MSG_LEN 256

  typedef struct {
    uint8_t data[MAX_MSG_LEN]; // max size of the message
    uint8_t size; // size of the message 
    uint8_t priority; // priority of the message
    uint32_t time; // time of insertion of the message
  }msg_container_t;

  typedef struct {
    msg_container_t elements[MAX_Q_SIZE];
    uint8_t N;
  }pqueue_t;

  uint8_t pq_isless(const msg_container_t a, const msg_container_t b);

  uint8_t pq_init(pqueue_t *queue);

  uint8_t pq_push(pqueue_t *queue, const msg_container_t *element);

  uint8_t pq_getmax(pqueue_t *queue, msg_container_t *max_element);

  uint8_t pq_get_max_by_size(pqueue_t *queue, msg_container_t *max_element, int32_t size);

  uint8_t pq_size(pqueue_t *queue);

  extern struct pqueue_t pprz_queue;
  extern struct msg_container_t pprz_msg;

#ifdef __cplusplus
}
#endif

#endif /* ____PRQUEUE_H */

/************************END OF FILE****/

