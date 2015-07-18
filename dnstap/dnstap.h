/* dnstap support for Unbound */

/*
 * Copyright (c) 2013-2014, Farsight Security, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 * notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 * notice, this list of conditions and the following disclaimer in the
 * documentation and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its
 * contributors may be used to endorse or promote products derived from
 * this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED
 * TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO,
 * PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR
 * OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF
 * ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#ifndef UNBOUND_DNSTAP_H
#define UNBOUND_DNSTAP_H

#include "dnstap/dnstap_config.h"
#include "dnstap/dnstap.pb-c.h"
#include "dnstap/pipe.h"
#include <pthread.h>

#ifdef USE_DNSTAP

struct config_file;
struct sldns_buffer;
#define DNSTAP_INITIAL_BUF_SIZE 256

typedef struct dt_msg {
	void *buf;
	size_t len_buf;
	Dnstap__Dnstap d;
	Dnstap__Message m;
} dt_msg_t;

typedef struct dt_message {
	uint16_t length;
	void *buffer;
} dt_message_t;

#define dt_message_size(MSG) sizeof(uint16_t) + MSG->length
#define dt_message_alloc(LENGTH) malloc(sizeof(uint16_t) + LENGTH)
#define dt_message_free(MSG) free(MSG->buffer); free(MSG)

typedef struct dt_env {
	uint16_t len_identity;
	uint8_t *identity;
	uint16_t len_version;
	uint8_t *version;

	pipe_t *so_pipe;
	pipe_producer_t *so_producer;
	pipe_consumer_t *so_consumer;
	pthread_t dt_worker;

	int so_socket;
	uint8_t *so_connected;
	uint8_t *dt_stopping;

	uint8_t log_resolver_query_messages			: 1;
	uint8_t log_resolver_response_messages	: 1;
	uint8_t log_client_query_messages				: 1;
	uint8_t log_client_response_messages		: 1;
	uint8_t log_forwarder_query_messages		: 1;
	uint8_t log_forwarder_response_messages	: 1;
} dt_env_t;

/**
 * Create dnstap environment object. Afterwards, call dt_apply_cfg() to fill in
 * the config variables and dt_init() to fill in the per-worker state. Each
 * worker needs a copy of this object but with its own I/O queue (the fq field
 * of the structure) to ensure lock-free access to its own per-worker circular
 * queue.  Duplicate the environment object if more than one worker needs to
 * share access to the dnstap I/O socket.
 * @param socket_path: path to dnstap logging socket, must be non-NULL.
 * @param num_workers: number of worker threads, must be > 0.
 * @return dt_env object, NULL on failure.
 */
dt_env_t *
dt_create(uint16_t port, uint8_t num_workers);

/**
 * Apply config settings.
 * @param env: dnstap environment object.
 * @param cfg: new config settings.
 */
void
dt_apply_cfg(dt_env_t *env, struct config_file *cfg);

/**
 * Initialize per-worker state in dnstap environment object.
 * @param env: dnstap environment object to initialize, created with dt_create().
 * @return: true on success, false on failure.
 */
int
dt_init(dt_env_t *env);

/**
 * Delete dnstap environment object. Closes dnstap I/O socket and deletes all
 * per-worker I/O queues.
 */
void
dt_delete(dt_env_t *env);

/**
 * Worker for writing DNSTap mesasges to a socket
 */
void *
__dt_worker(void *);

uint8_t
__dt_so_connect(dt_env_t *env, struct sockaddr_in so_service);

/**
 * Create and send a new dnstap "Message" event of type CLIENT_QUERY.
 * @param env: dnstap environment object.
 * @param qsock: address/port of client.
 * @param cptype: comm_udp or comm_tcp.
 * @param qmsg: query message.
 */
void
dt_msg_send_client_query(dt_env_t *env,
	struct sockaddr_storage *qsock,
	enum comm_point_type cptype,
	struct sldns_buffer *qmsg);

/**
 * Create and send a new dnstap "Message" event of type CLIENT_RESPONSE.
 * @param env: dnstap environment object.
 * @param qsock: address/port of client.
 * @param cptype: comm_udp or comm_tcp.
 * @param rmsg: response message.
 */
void
dt_msg_send_client_response(dt_env_t *env,
	struct sockaddr_storage *qsock,
	enum comm_point_type cptype,
	struct sldns_buffer *rmsg);

/**
 * Create and send a new dnstap "Message" event of type RESOLVER_QUERY or
 * FORWARDER_QUERY. The type used is dependent on the value of the RD bit
 * in the query header.
 * @param env: dnstap environment object.
 * @param rsock: address/port of server the query is being sent to.
 * @param cptype: comm_udp or comm_tcp.
 * @param zone: query zone.
 * @param zone_len: length of zone.
 * @param qmsg: query message.
 */
void
dt_msg_send_outside_query(dt_env_t *env,
	struct sockaddr_storage *rsock,
	enum comm_point_type cptype,
	uint8_t *zone, size_t zone_len,
	struct sldns_buffer *qmsg);

/**
 * Create and send a new dnstap "Message" event of type RESOLVER_RESPONSE or
 * FORWARDER_RESPONSE. The type used is dependent on the value of the RD bit
 * in the query header.
 * @param env: dnstap environment object.
 * @param rsock: address/port of server the response was received from.
 * @param cptype: comm_udp or comm_tcp.
 * @param zone: query zone.
 * @param zone_len: length of zone.
 * @param qbuf: outside_network's qbuf key.
 * @param qbuf_len: length of outside_network's qbuf key.
 * @param qtime: time query message was sent.
 * @param rtime: time response message was sent.
 * @param rmsg: response message.
 */
void
dt_msg_send_outside_response(dt_env_t *env,
	struct sockaddr_storage *rsock,
	enum comm_point_type cptype,
	uint8_t *zone, size_t zone_len,
	uint8_t *qbuf, size_t qbuf_len,
	const struct timeval *qtime,
	const struct timeval *rtime,
	struct sldns_buffer *rmsg);

#endif /* USE_DNSTAP */
#endif /* UNBOUND_DNSTAP_H */
