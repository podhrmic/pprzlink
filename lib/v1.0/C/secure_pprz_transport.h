/*
 * Copyright (C) 2003  Pascal Brisset, Antoine Drouin
 * Copyright (C) 2015  Gautier Hattenberger <gautier.hattenberger@enac.fr>
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
 * @file pprzlink/pprz_transport.h
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

#ifndef SECURE_PPRZ_TRANSPORT_H
#define SECURE_PPRZ_TRANSPORT_H

#ifdef __cplusplus
extern "C" {
#endif

#include <inttypes.h>
#include <stdbool.h>
#include "pprzlink/pprzlink_transport.h"
#include "pprzlink/pprzlink_device.h"

// Start byte
#define PPRZ_STX  0x99
#define PPRZ_MAX_MSG_LEN 256
#define PPRZ_MAX_Q_SIZE 10

#define PPRZ_PROTECTION_INTERVAL_MS 6 // TODO: make user definable?
#define PPRZ_US_PER_BYTE 170 // at 57600 baud, TODO: make user definable

#define PPRZ_MSG_SYNC_CHANNEL_ID 158 // TODO: link to messages.xml?

enum SecurePprzTransportStatus {
  SECURE_PPRZ_TRANSPORT_STATUS_WAITING_FOR_SYNC_CHANNEL,
  SECURE_PPRZ_TRANSPORT_STATUS_WAITING_FOR_PROTECTION_INTERVAL,
  SECURE_PPRZ_TRANSPORT_STATUS_TRANSMITTING,
};

typedef uint32_t (*get_time_msec_t)(void);

struct msg_container_t {
    uint8_t data[PPRZ_MAX_MSG_LEN]; // max size of the message
    uint8_t size; // size of the message
    uint8_t priority; // priority of the message
    uint32_t time; // time of insertion of the message (ms), overflow in ~10hrs
};

// 10x256 = 2560 = 2.5kb additional memory
struct pqueue_t {
    struct msg_container_t elements[PPRZ_MAX_Q_SIZE];
    uint8_t N;
};


/* PPRZ Transport
 */
struct spprz_transport {
  // generic reception interface
  struct transport_rx trans_rx;
  // specific pprz transport_rx variables
  uint8_t status;
  uint8_t payload_idx;
  uint8_t ck_a_rx, ck_b_rx;
  // generic transmission interface
  struct transport_tx trans_tx;
  // specific pprz transport_tx variables
  uint8_t ck_a_tx, ck_b_tx;

  // message queue
  struct pqueue_t queue;

  // transport structure for queue insertion
  struct msg_container_t msg;

  // transport structure for queue extraction
  struct msg_container_t msg_tx;

  // get current time function pointer
  get_time_msec_t get_time_msec;

  // scheduling variables
  uint8_t delay; // in ms
  uint32_t last_rx_time; // in ms
  uint32_t t_2; // in ms
  enum SecurePprzTransportStatus scheduler_status; // scheduling status
};





// Init function
extern void spprz_transport_init(struct spprz_transport *t, uint32_t (*get_time_msec_t)(void));

// Checking new data and parsing
extern void spprz_check_and_parse(struct link_device *dev, struct spprz_transport *t, uint8_t *buf, bool *msg_available);

// Parsing function, only needed for modules doing their own parsing
// without using the pprz_check_and_parse function
extern void parse_spprz(struct spprz_transport *t, uint8_t c);

// Sending function - release messages from the queue
extern void spprz_scheduling_periodic(struct link_device *dev, struct spprz_transport *t);


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
 * Return 1 if the queue has size of 0
 */
uint8_t pq_isempty(struct pqueue_t *queue);


#ifdef __cplusplus
} /* extern "C" */
#endif

#endif /* SECURE_PPRZ_TRANSPORT_H */

