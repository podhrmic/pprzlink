/*
 * Copyright (C) 2006  Pascal Brisset, Antoine Drouin
 * Copyright (C) 2014-2015  Gautier Hattenberger <gautier.hattenberger@enac.fr>
 *
 * This file is part of paparazzi.
 *
 * paparazzi is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.
 *
 * paparazzi is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with paparazzi; see the file COPYING.  If not, see
 * <http://www.gnu.org/licenses/>.
 *
 */

/**
 * @file pprzlink/pprz_transport.c
 *
 * Building and parsing Paparazzi frames.
 *
 * Pprz frame:
 *
 * |STX|length|... payload=(length-4) bytes ...|Checksum A|Checksum B|
 *
 * where checksum is computed over length and payload:
 * @code
 * ck_A = ck_B = length
 * for each byte b in payload
 *     ck_A += b;
 *     ck_b += ck_A;
 * @endcode
 */

#include <inttypes.h>
#include "pprzlink/secure_pprz_transport.h"
#include "secure_pprz_transport.h" // DUMMY include

// PPRZ parsing state machine
#define UNINIT      0
#define GOT_STX     1
#define GOT_LENGTH  2
#define GOT_PAYLOAD 3
#define GOT_CRC1    4

#define GOT_SYNC_CHANNEL 158 //<message name="SYNC_CHANNEL" id="158">
#define GOT_PING 8 // <message name="PING" id="8"/>

#define msg_put_byte(_t,_b) {\
    _t->msg.data[_t->msg.size] = _b;\
    _t->msg.size++;\
}

/**
 * compare two message containers
 */
uint8_t pq_isless(const struct msg_container_t a, const struct msg_container_t b);

/**
 * Initialize the message queue
 */
uint8_t pq_init(struct pqueue_t *queue);

/**
 * Push a message container into a queue
 */
uint8_t pq_push(struct pqueue_t *queue, const struct msg_container_t *element);

/**
 * Get the most important element from the queue
 * If two or more elements have the same priority, it depends on the time of insertion
 */
uint8_t pq_getmax(struct pqueue_t *queue, struct msg_container_t *max_element);

/**
 * Return the most important elements that are smaller than the size
 */
uint8_t pq_get_max_by_size(struct pqueue_t *queue, struct msg_container_t *max_element, int32_t size);

/**
 * Number of messages stored in the queue
 */
uint8_t pq_size(struct pqueue_t *queue);

/**
 * Return a copy of the max element from the queue
 */
uint8_t pq_peek(struct pqueue_t *queue, struct msg_container_t *max_element);

/**
 * Accumulate checksum. No change from the regular transport
 */
static void accumulate_checksum(struct spprz_transport *trans, const uint8_t byte)
{
  trans->ck_a_tx += byte;
  trans->ck_b_tx += trans->ck_a_tx;
}

static void put_priority(struct spprz_transport *trans, struct link_device *dev __attribute__((unused)),
                         long fd __attribute__((unused)), uint8_t prio)
{
  trans->msg.priority = prio;
}

/**
 * Put bytes into a buffer
 */
static void put_bytes(struct spprz_transport *trans, struct link_device *dev, long fd,
                      enum TransportDataType type __attribute__((unused)), enum TransportDataFormat format __attribute__((unused)),
                      const void *bytes, uint16_t len)
{
  const uint8_t *b = (const uint8_t *) bytes;
  int i;
  for (i = 0; i < len; i++) {
    accumulate_checksum(trans, b[i]);
  }
  //dev->put_buffer(dev->periph, fd, b, len);
  for (uint8_t i=0;i<len;i++) {
    msg_put_byte(trans,b[i]);
  }
}

/**
 * Identical to a regular put_byte
 */
static void put_named_byte(struct spprz_transport *trans, struct link_device *dev, long fd,
                           enum TransportDataType type __attribute__((unused)), enum TransportDataFormat format __attribute__((unused)),
                           uint8_t byte, const char *name __attribute__((unused)))
{
  accumulate_checksum(trans, byte);
  //dev->put_byte(dev->periph, fd, byte);
  msg_put_byte(trans,byte);
}


/**
 * Return the size of the payload plus 4 byte protocol overhead (STX + len + ck_a + ck_b = 4)
 */
static uint8_t size_of(struct spprz_transport *trans __attribute__((unused)), uint8_t len)
{
  // message length: payload + protocol overhead (STX + len + ck_a + ck_b = 4)
  return len + 4;
}

/**
 * Start putting bytes into the interim message structure
 */
static void start_message(struct spprz_transport *trans, struct link_device *dev, long fd, uint8_t payload_len)
{
  // clear buffer
  memset(trans->msg,0,sizeof(struct msg_container_t));

  // insert header
  // dev->put_byte(dev->periph, fd, PPRZ_STX);
  trans->msg.data[trans->msg.size] = PPRZ_STX;
  trans->msg.size++;

  const uint8_t msg_len = size_of(trans, payload_len);

  //dev->put_byte(dev->periph, fd, msg_len);
  msg_put_byte(trans,msg_len);

  trans->ck_a_tx = msg_len;
  trans->ck_b_tx = msg_len;

  // set priority, default is 1
  trans->msg.priority = 1;
}


/**
 * Finalize message and insert it into a queue
 */
static void end_message(struct spprz_transport *trans, struct link_device *dev, long fd)
{
  //dev->put_byte(dev->periph, fd, trans->ck_a_tx);
  //dev->put_byte(dev->periph, fd, trans->ck_b_tx);
  msg_put_byte(trans,trans->ck_a_tx);
  msg_put_byte(trans,trans->ck_b_tx);

  trans->msg.time = trans->get_time_usec() / 1000;

  //dev->send_message(dev->periph, fd);
  if (pq_push(trans->queue, trans->msg) == 0) {
    // TODO: a placeholder for a error handling (if the queue is full)
    overrun(trans, dev);
  }
}

/**
 * Increment the overrun error
 */
static void overrun(struct spprz_transport *trans __attribute__((unused)), struct link_device *dev)
{
  dev->nb_ovrn++;
}


/**
 * No change here
 */
static void count_bytes(struct spprz_transport *trans __attribute__((unused)), struct link_device *dev, uint8_t bytes)
{
  dev->nb_bytes += bytes;
}

/**
 * Returns 1 if there is space available in the queue
 */
static int check_available_space(struct spprz_transport *trans __attribute__((unused)), struct link_device *dev,
                                 long *fd, uint16_t bytes)
{
  //return dev->check_free_space(dev->periph, fd, bytes);
  if (pq_size(trans->queue) < PPRZ_MAX_Q_SIZE) {
    return 1; // space available
  } else {
    return 0; // the queue is full
  }
}

/**
 * Init secure pprz transport structure
 */
void spprz_transport_init(struct spprz_transport *t, get_time_usec_t get_time_usec)
{
  t->status = UNINIT;
  t->trans_rx.msg_received = false;
  t->trans_tx.size_of = (size_of_t) size_of;
  t->trans_tx.check_available_space = (check_available_space_t) check_available_space;
  t->trans_tx.put_bytes = (put_bytes_t) put_bytes;
  t->trans_tx.put_named_byte = (put_named_byte_t) put_named_byte;
  t->trans_tx.start_message = (start_message_t) start_message;
  t->trans_tx.end_message = (end_message_t) end_message;
  t->trans_tx.overrun = (overrun_t) overrun;
  t->trans_tx.count_bytes = (count_bytes_t) count_bytes;
  t->trans_tx.impl = (void *)(t);
  t->get_time_usec = get_time_usec;
  t->trans_tx.put_priority = (put_priority_t) put_priority;

  // init the queue
  pq_init(t->queue);

  // init the interim message
  memset(t->msg,0,sizeof(struct msg_container_t));

  // scheduling variables
  t->delay = 0;
  t->last_rx_time = 0;
  t->scheduler_status = SECURE_PPRZ_TRANSPORT_STATUS_WAITING_FOR_SYNC_CHANNEL;
}


/**
 * Parsing function - unchanged
 */
void parse_spprz(struct spprz_transport *t, uint8_t c)
{
  switch (t->status) {
    case UNINIT:
      if (c == PPRZ_STX) {
        t->status++;
      }
      break;
    case GOT_STX:
      if (t->trans_rx.msg_received) {
        t->trans_rx.ovrn++;
        goto error;
      }
      t->trans_rx.payload_len = c - 4; /* Counting STX, LENGTH and CRC1 and CRC2 */
      t->ck_a_rx = t->ck_b_rx = c;
      t->status++;
      t->payload_idx = 0;
      break;
    case GOT_LENGTH:
      t->trans_rx.payload[t->payload_idx] = c;
      t->ck_a_rx += c; t->ck_b_rx += t->ck_a_rx;
      t->payload_idx++;
      if (t->payload_idx == t->trans_rx.payload_len) {
        t->status++;
      }
      break;
    case GOT_PAYLOAD:
      if (c != t->ck_a_rx) {
        goto error;
      }
      t->status++;
      break;
    case GOT_CRC1:
      if (c != t->ck_b_rx) {
        goto error;
      }
      t->trans_rx.msg_received = true;
      goto restart;
    default:
      goto error;
  }
  return;
error:
  t->trans_rx.error++;
restart:
  t->status = UNINIT;
  return;
}


/**
 *  Parsing a frame data and copy the payload to the datalink buffer
 *  All the logic over payload is done in paparazzi itself
 */
void spprz_check_and_parse(struct link_device *dev, struct spprz_transport *trans, uint8_t *buf, bool *msg_available)
{
  uint8_t i;
  if (dev->char_available(dev->periph)) {
    while (dev->char_available(dev->periph) && !trans->trans_rx.msg_received) {
      parse_spprz(trans, dev->get_byte(dev->periph));
    }
    if (trans->trans_rx.msg_received) {
      for (i = 0; i < trans->trans_rx.payload_len; i++) {
        buf[i] = trans->trans_rx.payload[i];
      }
      *msg_available = true;
      trans->trans_rx.msg_received = false;
    }
  }
}

/**
 * Main scheduling function, called from telemetry_periodic at TELEMETRY_FREQUENCY
 */
void spprz_scheduling_periodic(struct link_device *dev, struct spprz_transport *trans) {
  // copy what is in the rustlink implementation
}


uint8_t pq_isless(const struct msg_container_t a, const struct msg_container_t b)
{
  if (a.priority > b.priority)
    return 0;
  if (a.priority < b.priority)
    return 1;
  if (a.time < b.time)
    return 0;
  return 1;
}

uint8_t pq_init(struct pqueue_t *queue)
{
  memset(queue, 0, sizeof(queue));
  return queue->N = 0;
}

uint8_t pq_size(struct pqueue_t *queue)
{
  return queue->N;
}

uint8_t pq_push(struct pqueue_t *queue, const struct msg_container_t* element)
{
  if (queue->N >= PPRZ_MAX_Q_SIZE)
    return 0;
  memcpy(&queue->elements[queue->N], element, sizeof(struct msg_container_t));
  queue->N++;
  return 1;
}

uint8_t pq_getmax(struct pqueue_t *queue, struct msg_container_t *max_element)
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

  memcpy(max_element, &queue->elements[max_id], sizeof(struct msg_container_t));
  memcpy(&queue->elements[max_id], &queue->elements[queue->N - 1],
      sizeof(struct msg_container_t));
  queue->N--;

  return 1;

}

uint8_t pq_get_max_by_size(struct pqueue_t *queue, struct msg_container_t *max_element,
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

  memcpy(max_element, &queue->elements[max_id], sizeof(struct msg_container_t));
  memcpy(&queue->elements[max_id], &queue->elements[queue->N - 1],
      sizeof(struct msg_container_t));
  queue->N--;

  return 1;
}

uint8_t pq_peek(struct pqueue_t *queue, struct msg_container_t *max_element)
{
  uint8_t max_id = 0;
  uint8_t i;

  if (queue->N <= 0)
    return 0;
  for (i = 1; i < queue->N; i++)
    if (pq_isless(queue->elements[max_id], queue->elements[i]))
      max_id = i;

  memcpy(max_element, &queue->elements[max_id], sizeof(struct msg_container_t));
  return 1;
}
