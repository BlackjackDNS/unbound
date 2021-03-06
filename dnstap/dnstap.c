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

#include "dnstap/dnstap_config.h"

#ifdef USE_DNSTAP

#include "config.h"

#include <protobuf-c/protobuf-c.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>

#include "sldns/sbuffer.h"
#include "util/config_file.h"
#include "util/net_help.h"
#include "util/netevent.h"
#include "util/log.h"

#include "dnstap/dnstap.h"

static int
dt_pack(const Dnstap__Dnstap *d, void **buf, size_t *sz)
{
	ProtobufCBufferSimple sbuf;
	memset(&sbuf, 0, sizeof(sbuf));

	sbuf.base.append = protobuf_c_buffer_simple_append;
	sbuf.len = 0;
	sbuf.alloced = DNSTAP_INITIAL_BUF_SIZE;
	sbuf.data = malloc(sbuf.alloced);

	if (sbuf.data == NULL) return 0;
	sbuf.must_free_data = 1;

	*sz = dnstap__dnstap__pack_to_buffer(d, (ProtobufCBuffer *) &sbuf);
	if (sbuf.data == NULL) return 0;

	*buf = sbuf.data;
	return 1;
}

static void
dt_send(const dt_env_t *env, void *buf, size_t len_buf)
{
	verbose(VERB_OPS, "dnstap: %s (unbound@%s)", env->identity, env->version);

	dt_message_t *event = dt_message_alloc(len_buf);
	event->length = len_buf;
	event->buffer = buf;
	verbose(VERB_OPS, "dnstap: queueing event (length %d)", event->length);

	pipe_push(env->so_producer, &event, 1);
	verbose(VERB_OPS, "dnstap: queued event");
}

static void
dt_msg_init(const dt_env_t *env,
	dt_msg_t *dm,
	Dnstap__Message__Type mtype)
{
	memset(dm, 0, sizeof(*dm));
	dm->d.base.descriptor = &dnstap__dnstap__descriptor;
	dm->m.base.descriptor = &dnstap__message__descriptor;
	dm->d.type = DNSTAP__DNSTAP__TYPE__MESSAGE;
	dm->d.message = &dm->m;
	dm->m.type = mtype;
	if (env->identity != NULL) {
		dm->d.identity.data = (uint8_t *) env->identity;
		dm->d.identity.len = (size_t) env->len_identity;
		dm->d.has_identity = 1;
	}
	if (env->version != NULL) {
		dm->d.version.data = (uint8_t *) env->version;
		dm->d.version.len = (size_t) env->len_version;
		dm->d.has_version = 1;
	}
}

dt_env_t *
dt_create(uint16_t port, uint8_t num_workers)
{
	log_assert(port > 0);
	log_assert(num_workers > 0);

	dt_env_t *env = (dt_env_t *) malloc(sizeof(dt_env_t));
	if (!env) return NULL;

	// Flags. Initial valuse are set here, and each is set again, only once,
	// from another function, possibly in another thread; otherwise,
	// they're only ever read.
	env->so_connected = malloc(sizeof(uint8_t));
	env->dt_stopping = malloc(sizeof(uint8_t));

	*(env->so_connected) = 0;
	*(env->dt_stopping) = 0;

	env->so_pipe = pipe_new(sizeof(void *), 0);

	// These are used in the dt_worker therad. Unbound workers
	// create their own producers
	env->so_consumer = pipe_consumer_new(env->so_pipe);
	env->so_producer = pipe_producer_new(env->so_pipe);
	pthread_create(&env->dt_worker, NULL, __dt_worker, env);

	return env;
}

void *
__dt_worker(void *arg) {
	verbose(VERB_OPS, "dnstap: starting dt_worker thread");

	dt_env_t *env = (dt_env_t *) arg;
	struct sockaddr_in so_service;

	so_service.sin_family = AF_INET;
	so_service.sin_port = htons(5354);
	so_service.sin_addr.s_addr = inet_addr("127.0.0.1");
	memset(so_service.sin_zero, 0, sizeof so_service.sin_zero);

	if(!__dt_so_connect(env, so_service)) return NULL;

	// Pop events off of the queue
	dt_message_t * event;

	while(pipe_pop(env->so_consumer, &event, 1)) {
		if(send(env->so_socket, event, dt_message_size(event), 0) < 0) {
			verbose(VERB_OPS, "dnstap: error sending message: %s. Trying to reconnect", strerror(errno));

			// Requeue the event for later
			pipe_push(env->so_producer, &event, 1);

			// And try to reconnect
			close(env->so_socket);
			if(!__dt_so_connect(env, so_service)) return NULL;
		} else {
			verbose(VERB_OPS, "dnstap: sent event to dt_service");
			dt_message_free(event);
		}
	}

	verbose(VERB_OPS, "dnstap: stopping dt_worker thread");
	close(env->so_socket);
	pipe_consumer_free(env->so_consumer);
}

uint8_t
__dt_so_connect(dt_env_t *env, struct sockaddr_in so_service) {
	while(1) {
		if(*(env->dt_stopping)) return 0;

		verbose(VERB_OPS, "dnstap: trying to connect to %s:%d", "127.0.0.1", 5354);
		if((env->so_socket = socket(PF_INET, SOCK_STREAM, 0)) < 0) {
			verbose(VERB_OPS, "dnstap: error creating socket: %s", strerror(errno));
			return 0;
		}

		if(connect(env->so_socket, (struct sockaddr *) &so_service, sizeof so_service) > -1) break;
		verbose(VERB_OPS, "dnstap: error connecting to socket: %s", strerror(errno));

		// Try again in 5 seconds
		close(env->so_socket);
		sleep(5);
	}

	*(env->so_connected) = 1;
	verbose(VERB_OPS, "dnstap: connected to %s:%d", "127.0.0.1", 5354);
	return 1;
}

void
dt_apply_cfg(dt_env_t *env, struct config_file *cfg)
{
	if (!cfg->dnstap) return;

	if (cfg->dnstap_send_identity) {
		free(env->identity);
		env->identity = strdup(cfg->identity);
		env->len_identity = (uint16_t) strlen(env->identity);
		verbose(VERB_OPS, "dnstap: identity field set to \"%s\"", env->identity);
	}

	if (cfg->dnstap_send_version) {
		free(env->version);
		env->version = strdup(cfg->version);
		env->len_version = (uint16_t) strlen(env->version);
		verbose(VERB_OPS, "dnstap: version field set to \"%s\"", env->version);
	}

	if ((env->log_resolver_query_messages = (uint8_t) cfg->dnstap_log_resolver_query_messages))
			verbose(VERB_OPS, "dnstap: Message/RESOLVER_QUERY enabled");

	if ((env->log_resolver_response_messages = (uint8_t) cfg->dnstap_log_resolver_response_messages))
			verbose(VERB_OPS, "dnstap: Message/RESOLVER_RESPONSE enabled");

	if ((env->log_client_query_messages = (uint8_t) cfg->dnstap_log_client_query_messages))
			verbose(VERB_OPS, "dnstap: Message/CLIENT_QUERY enabled");

	if ((env->log_client_response_messages = (uint8_t) cfg->dnstap_log_client_response_messages))
			verbose(VERB_OPS, "dnstap: Message/CLIENT_RESPONSE enabled");

	if ((env->log_forwarder_query_messages = (uint8_t) cfg->dnstap_log_forwarder_query_messages))
			verbose(VERB_OPS, "dnstap: Message/FORWARDER_QUERY enabled");

	if ((env->log_forwarder_response_messages = (uint8_t) cfg->dnstap_log_forwarder_response_messages))
			verbose(VERB_OPS, "dnstap: Message/FORWARDER_RESPONSE enabled");
}

int
dt_init(dt_env_t *env)
{
	env->so_producer = pipe_producer_new(env->so_pipe);
	return 1;
}

void
dt_delete(dt_env_t *env)
{
	if (!env) return;
	verbose(VERB_OPS, "cleanup dnstap environment");

	free(env->identity);
	free(env->version);

	// Wait for all unbound_workers' producers to drain
	*(env->dt_stopping) = 1;

	pipe_producer_free(env->so_producer);
	pthread_join(env->dt_worker, NULL);
	free(env);
}

static void
dt_fill_timeval(const struct timeval *tv,
		uint64_t *time_sec, protobuf_c_boolean *has_time_sec,
		uint32_t *time_nsec, protobuf_c_boolean *has_time_nsec)
{
#ifndef S_SPLINT_S
	*time_sec = tv->tv_sec;
	*time_nsec = tv->tv_usec * 1000;
#endif
	*has_time_sec = 1;
	*has_time_nsec = 1;
}

static void
dt_fill_buffer(sldns_buffer *b, ProtobufCBinaryData *p, protobuf_c_boolean *has)
{
	log_assert(b != NULL);
	p->len = sldns_buffer_limit(b);
	p->data = sldns_buffer_begin(b);
	*has = 1;
}

static void
dt_msg_fill_net(dt_msg_t *dm,
		struct sockaddr_storage *ss,
		enum comm_point_type cptype,
		ProtobufCBinaryData *addr, protobuf_c_boolean *has_addr,
		uint32_t *port, protobuf_c_boolean *has_port)
{
	log_assert(ss->ss_family == AF_INET6 || ss->ss_family == AF_INET);
	if (ss->ss_family == AF_INET6) {
		struct sockaddr_in6 *s = (struct sockaddr_in6 *) ss;

		/* socket_family */
		dm->m.socket_family = DNSTAP__SOCKET_FAMILY__INET6;
		dm->m.has_socket_family = 1;

		/* addr: query_address or response_address */
		addr->data = s->sin6_addr.s6_addr;
		addr->len = 16; /* IPv6 */
		*has_addr = 1;

		/* port: query_port or response_port */
		*port = ntohs(s->sin6_port);
		*has_port = 1;
	} else if (ss->ss_family == AF_INET) {
		struct sockaddr_in *s = (struct sockaddr_in *) ss;

		/* socket_family */
		dm->m.socket_family = DNSTAP__SOCKET_FAMILY__INET;
		dm->m.has_socket_family = 1;

		/* addr: query_address or response_address */
		addr->data = (uint8_t *) &s->sin_addr.s_addr;
		addr->len = 4; /* IPv4 */
		*has_addr = 1;

		/* port: query_port or response_port */
		*port = ntohs(s->sin_port);
		*has_port = 1;
	}

	log_assert(cptype == comm_udp || cptype == comm_tcp);
	if (cptype == comm_udp) {
		/* socket_protocol */
		dm->m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__UDP;
		dm->m.has_socket_protocol = 1;
	} else if (cptype == comm_tcp) {
		/* socket_protocol */
		dm->m.socket_protocol = DNSTAP__SOCKET_PROTOCOL__TCP;
		dm->m.has_socket_protocol = 1;
	}
}

void
dt_msg_send_client_query(dt_env_t *env,
	struct sockaddr_storage *qsock,
	enum comm_point_type cptype,
	sldns_buffer *qmsg)
{
	dt_msg_t dm;
	struct timeval qtime;

	gettimeofday(&qtime, NULL);

	/* type */
	dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__CLIENT_QUERY);

	/* query_time */
	dt_fill_timeval(&qtime,
		&dm.m.query_time_sec, &dm.m.has_query_time_sec,
		&dm.m.query_time_nsec, &dm.m.has_query_time_nsec);

	/* query_message */
	dt_fill_buffer(qmsg, &dm.m.query_message, &dm.m.has_query_message);

	/* socket_family, socket_protocol, query_address, query_port */
	log_assert(cptype == comm_udp || cptype == comm_tcp);
	dt_msg_fill_net(&dm, qsock, cptype,
		&dm.m.query_address, &dm.m.has_query_address,
		&dm.m.query_port, &dm.m.has_query_port);

	if (dt_pack(&dm.d, &dm.buf, &dm.len_buf))
		dt_send(env, dm.buf, dm.len_buf);
}

void
dt_msg_send_client_response(dt_env_t *env,
			    struct sockaddr_storage *qsock,
			    enum comm_point_type cptype,
			    sldns_buffer *rmsg)
{
	dt_msg_t dm;
	struct timeval rtime;

	gettimeofday(&rtime, NULL);

	/* type */
	dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__CLIENT_RESPONSE);

	/* response_time */
	dt_fill_timeval(&rtime,
			&dm.m.response_time_sec, &dm.m.has_response_time_sec,
			&dm.m.response_time_nsec, &dm.m.has_response_time_nsec);

	/* response_message */
	dt_fill_buffer(rmsg, &dm.m.response_message, &dm.m.has_response_message);

	/* socket_family, socket_protocol, query_address, query_port */
	log_assert(cptype == comm_udp || cptype == comm_tcp);
	dt_msg_fill_net(&dm, qsock, cptype,
			&dm.m.query_address, &dm.m.has_query_address,
			&dm.m.query_port, &dm.m.has_query_port);

	if (dt_pack(&dm.d, &dm.buf, &dm.len_buf))
		dt_send(env, dm.buf, dm.len_buf);
}

void
dt_msg_send_outside_query(dt_env_t *env,
			  struct sockaddr_storage *rsock,
			  enum comm_point_type cptype,
			  uint8_t *zone, size_t zone_len,
			  sldns_buffer *qmsg)
{
	dt_msg_t dm;
	struct timeval qtime;
	uint16_t qflags;

	gettimeofday(&qtime, NULL);
	qflags = sldns_buffer_read_u16_at(qmsg, 2);

	/* type */
	if (qflags & BIT_RD) {
		if (!env->log_forwarder_query_messages)
			return;
		dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__FORWARDER_QUERY);
	} else {
		if (!env->log_resolver_query_messages)
			return;
		dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__RESOLVER_QUERY);
	}

	/* query_zone */
	dm.m.query_zone.data = zone;
	dm.m.query_zone.len = zone_len;
	dm.m.has_query_zone = 1;

	/* query_time_sec, query_time_nsec */
	dt_fill_timeval(&qtime,
			&dm.m.query_time_sec, &dm.m.has_query_time_sec,
			&dm.m.query_time_nsec, &dm.m.has_query_time_nsec);

	/* query_message */
	dt_fill_buffer(qmsg, &dm.m.query_message, &dm.m.has_query_message);

	/* socket_family, socket_protocol, response_address, response_port */
	log_assert(cptype == comm_udp || cptype == comm_tcp);
	dt_msg_fill_net(&dm, rsock, cptype,
			&dm.m.response_address, &dm.m.has_response_address,
			&dm.m.response_port, &dm.m.has_response_port);

	if (dt_pack(&dm.d, &dm.buf, &dm.len_buf))
		dt_send(env, dm.buf, dm.len_buf);
}

void
dt_msg_send_outside_response(dt_env_t *env,
	struct sockaddr_storage *rsock,
	enum comm_point_type cptype,
	uint8_t *zone, size_t zone_len,
	uint8_t *qbuf, size_t qbuf_len,
	const struct timeval *qtime,
	const struct timeval *rtime,
	sldns_buffer *rmsg)
{
	dt_msg_t dm;
	uint16_t qflags;

	log_assert(qbuf_len >= sizeof(qflags));
	memcpy(&qflags, qbuf, sizeof(qflags));
	qflags = ntohs(qflags);

	/* type */
	if (qflags & BIT_RD) {
		if (!env->log_forwarder_response_messages)
			return;
		dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__FORWARDER_RESPONSE);
	} else {
		if (!env->log_resolver_query_messages)
			return;
		dt_msg_init(env, &dm, DNSTAP__MESSAGE__TYPE__RESOLVER_RESPONSE);
	}

	/* query_zone */
	dm.m.query_zone.data = zone;
	dm.m.query_zone.len = zone_len;
	dm.m.has_query_zone = 1;

	/* query_time_sec, query_time_nsec */
	dt_fill_timeval(qtime,
			&dm.m.query_time_sec, &dm.m.has_query_time_sec,
			&dm.m.query_time_nsec, &dm.m.has_query_time_nsec);

	/* response_time_sec, response_time_nsec */
	dt_fill_timeval(rtime,
			&dm.m.response_time_sec, &dm.m.has_response_time_sec,
			&dm.m.response_time_nsec, &dm.m.has_response_time_nsec);

	/* response_message */
	dt_fill_buffer(rmsg, &dm.m.response_message, &dm.m.has_response_message);

	/* socket_family, socket_protocol, response_address, response_port */
	log_assert(cptype == comm_udp || cptype == comm_tcp);
	dt_msg_fill_net(&dm, rsock, cptype,
			&dm.m.response_address, &dm.m.has_response_address,
			&dm.m.response_port, &dm.m.has_response_port);

	if (dt_pack(&dm.d, &dm.buf, &dm.len_buf))
		dt_send(env, dm.buf, dm.len_buf);
}

#endif /* USE_DNSTAP */
