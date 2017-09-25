#include "prqueue.h"

uint8_t pq_isless(const msg_container_t a, const msg_container_t b)
{
  if (a.priority > b.priority)
    return 0;
  if (a.priority < b.priority)
    return 1;
	if (a.time < b.time)
    return 0;
  return 1;
}

uint8_t pq_init(pqueue_t *queue)
{
  return queue->N = 0;
}

uint8_t pq_size(pqueue_t *queue)
{
  return queue->N;
}

uint8_t pq_push(pqueue_t *queue, const msg_container_t* element)
{
  if (queue->N >= MAX_Q_SIZE)
    return 0;
  memcpy(&queue->elements[queue->N], element, sizeof(msg_container_t));
  queue->N++;
  return 1;
}

uint8_t pq_getmax(pqueue_t *queue, msg_container_t *max_element)
{
  uint8_t max_id = 0;
  uint8_t i = 0;

  if (queue->N <= 0)
    return 0;
  if (queue->N > 1)
    max_id = 0;

  for (i = 1; i < queue->N; i++)
    if (pq_isless(queue->elements[max_id], queue->elements[i]))
      max_id = i;

  memcpy(max_element, &queue->elements[max_id], sizeof(msg_container_t));
  memcpy(&queue->elements[max_id], &queue->elements[queue->N - 1],
      sizeof(msg_container_t));
  queue->N--;

  return 1;

}

uint8_t pq_get_max_by_size(pqueue_t *queue, msg_container_t *max_element,
    int32_t size)
{
  int8_t max_id = -1;
  uint8_t i = 0;

  if (size < 0)
    return 0;

  if (queue->N <= 0)
    return 0;

  for (i = 0; i < queue->N; i++)
    if (queue->elements[i].size < size) {
      max_id = i;
      break;
    }

  if (max_id < 0)
    return 0;

  for (i = 1; i < queue->N; i++)
    if (queue->elements[i].size < size
        && pq_isless(queue->elements[max_id], queue->elements[i]))
      max_id = i;

  memcpy(max_element, &queue->elements[max_id], sizeof(msg_container_t));
  memcpy(&queue->elements[max_id], &queue->elements[queue->N - 1],
      sizeof(msg_container_t));
  queue->N--;

  return 1;
}

uint8_t pq_peek(pqueue_t *queue, msg_container_t *max_element)
{
  uint8_t max_id = 0;
  uint8_t i;

  if (queue->N <= 0)
    return 0;
  for (i = 1; i < queue->N; i++)
    if (pq_isless(queue->elements[max_id], queue->elements[i]))
      max_id = i;

  memcpy(max_element, &queue->elements[max_id], sizeof(msg_container_t));
  return 1;
}
