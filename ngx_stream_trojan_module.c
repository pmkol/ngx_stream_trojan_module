#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_stream.h>

#include <netdb.h>
#include <stdio.h>
#include <sys/socket.h>

#include "ngx_stream_trojan_protocol.h"
#include "ngx_stream_trojan_http_proxy_protocol.h"
#include "ngx_stream_trojan_ip_prefer.h"
#include "ngx_stream_trojan_relay.h"
#include "ngx_stream_trojan_rules.h"
#include "ngx_stream_trojan_socks5_protocol.h"


#define NGX_STREAM_TROJAN_DEFAULT_BUFFER_SIZE 32768
#define NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE 1024
#define NGX_STREAM_TROJAN_UDP_BUFFER_SIZE \
    (NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 4)
#define NGX_STREAM_TROJAN_SOCKS5_UDP_SESSION_BUCKETS 64
#define NGX_STREAM_TROJAN_UDP_ROUTE_MAPPING_BUCKETS 64
#define NGX_STREAM_TROJAN_DEFAULT_ROUTE_CACHE_SIZE 1024
#define NGX_STREAM_TROJAN_DEFAULT_ROUTE_CACHE_TTL 60
#define NGX_STREAM_TROJAN_ROUTE_DRAIN_TIMEOUT 1000
#define NGX_STREAM_TROJAN_ROUTE_MAX_SYSTEM_ADDRS 8
#define NGX_STREAM_TROJAN_RESOLV_CONF "/etc/resolv.conf"


/*
 * Angie 1.12.0 changed ngx_resolver_t.connections from an ngx_array_t to
 * a linked-list head.  Keep the old check for Nginx and older Angie builds,
 * while using the pointer check required by the new resolver API.
 */
#if defined(angie_version) && (angie_version >= 1012000)
#define NGX_STREAM_TROJAN_RESOLVER_HAS_CONNECTIONS(r) \
    ((r) != NULL && (r)->connections != NULL)
#else
#define NGX_STREAM_TROJAN_RESOLVER_HAS_CONNECTIONS(r) \
    ((r) != NULL && (r)->connections.nelts != 0)
#endif


typedef enum {
    ngx_stream_trojan_outbound_direct = 0,
    ngx_stream_trojan_outbound_socks5
} ngx_stream_trojan_outbound_e;


typedef enum {
    ngx_stream_trojan_block_none = 0,
    ngx_stream_trojan_block_h3,
    ngx_stream_trojan_block_udp,
    ngx_stream_trojan_block_all
} ngx_stream_trojan_block_e;


typedef enum {
    ngx_stream_trojan_socks5_mode_tcp = 0,
    ngx_stream_trojan_socks5_mode_udp
} ngx_stream_trojan_socks5_mode_e;


typedef enum {
    ngx_stream_trojan_local_proxy_none = 0,
    ngx_stream_trojan_local_proxy_socks5,
    ngx_stream_trojan_local_proxy_http_proxy
} ngx_stream_trojan_local_proxy_e;


typedef enum {
    ngx_stream_trojan_route_resolve_off = 0,
    ngx_stream_trojan_route_resolve_literal,
    ngx_stream_trojan_route_resolve_lazy
} ngx_stream_trojan_route_resolve_e;


typedef enum {
    ngx_stream_trojan_route_drain_idle = 0,
    ngx_stream_trojan_route_drain_fast
} ngx_stream_trojan_route_drain_e;


typedef enum {
    ngx_stream_trojan_route_resolver_none = 0,
    ngx_stream_trojan_route_resolver_nginx,
    ngx_stream_trojan_route_resolver_system
} ngx_stream_trojan_route_resolver_e;


typedef enum {
    ngx_stream_trojan_socks5_step_greeting_write = 0,
    ngx_stream_trojan_socks5_step_method_read,
    ngx_stream_trojan_socks5_step_auth_write,
    ngx_stream_trojan_socks5_step_auth_read,
    ngx_stream_trojan_socks5_step_request_write,
    ngx_stream_trojan_socks5_step_response_read
} ngx_stream_trojan_socks5_step_e;


typedef enum {
    ngx_stream_trojan_in_socks5_step_greeting = 0,
    ngx_stream_trojan_in_socks5_step_method_write,
    ngx_stream_trojan_in_socks5_step_request,
    ngx_stream_trojan_in_socks5_step_response_write
} ngx_stream_trojan_in_socks5_step_e;


typedef enum {
    ngx_stream_trojan_in_http_step_request = 0,
    ngx_stream_trojan_in_http_step_response_write
} ngx_stream_trojan_in_http_step_e;


typedef struct {
    u_char data[NGX_STREAM_TROJAN_KEY_LEN];
} ngx_stream_trojan_key_t;


typedef struct {
    ngx_str_t    host;
    in_port_t    port;
    ngx_uint_t   set;
    ngx_uint_t   localhost;
} ngx_stream_trojan_server_ref_t;


typedef struct ngx_stream_trojan_srv_conf_s ngx_stream_trojan_srv_conf_t;
typedef struct ngx_stream_trojan_outbound_s ngx_stream_trojan_outbound_t;


typedef struct ngx_stream_trojan_route_cache_entry_s
    ngx_stream_trojan_route_cache_entry_t;


struct ngx_stream_trojan_route_cache_entry_s {
    ngx_queue_t                  queue;
    ngx_queue_t                  active_tcp;
    ngx_queue_t                  active_udp;
    ngx_stream_trojan_route_cache_entry_t *next;
    ngx_uint_t                   hash;
    ngx_uint_t                   generation;
    time_t                       expires;
    uint8_t                      type;
    uint8_t                      host_len;
    uint16_t                     port;
    u_char                       host[255];
    ngx_stream_trojan_outbound_t *outbound;
    unsigned                     valid:1;
    unsigned                     ttl:1;
    unsigned                     refreshing:1;
};


typedef struct {
    ngx_uint_t                    size;
    ngx_uint_t                    buckets_n;
    ngx_uint_t                    next_free;
    ngx_uint_t                    generation;
    ngx_queue_t                   lru;
    ngx_stream_trojan_route_cache_entry_t **buckets;
    ngx_stream_trojan_route_cache_entry_t  *entries;
} ngx_stream_trojan_route_cache_t;


struct ngx_stream_trojan_outbound_s {
    ngx_uint_t   type;
    ngx_uint_t   ip_prefer;
    ngx_uint_t   ip_prefer_set;
    ngx_uint_t   block;
    ngx_uint_t   block_set;
    ngx_str_t    tag;
    ngx_uint_t   match_all;
    ngx_addr_t  *socks5_server;
    ngx_str_t    socks5_username;
    ngx_str_t    socks5_password;
    ngx_uint_t   has_rules;
    ngx_stream_trojan_route_rules_t *matcher;
};


typedef struct ngx_stream_trojan_udp_route_mapping_s
    ngx_stream_trojan_udp_route_mapping_t;


struct ngx_stream_trojan_udp_route_mapping_s {
    ngx_queue_t                             queue;
    ngx_stream_trojan_udp_route_mapping_t *next;
    ngx_uint_t                             hash;
    ngx_msec_t                             last_seen;
    ngx_stream_trojan_addr_t               target;
    ngx_stream_trojan_outbound_t          *outbound;
    ngx_stream_trojan_route_cache_entry_t  *route_entry;
    unsigned                               route_linked:1;
    unsigned                               route_stale:1;
};


struct ngx_stream_trojan_srv_conf_s {
    ngx_flag_t   enable;
    ngx_flag_t   socks5_enable;
    ngx_flag_t   http_proxy_enable;
    ngx_flag_t   socks5_udp_enable;
    ngx_uint_t   local_proxy_type;
    ngx_uint_t   socks5_ref_set;
    ngx_array_t *keys;
    ngx_addr_t  *fallback;
    ngx_msec_t   connect_timeout;
    ngx_msec_t   timeout;
    ngx_msec_t   udp_timeout;
    size_t       buffer_size;
    ngx_array_t *outbounds;
    ngx_stream_trojan_srv_conf_t *effective;
    ngx_stream_trojan_server_ref_t socks5_ref;
    ngx_stream_trojan_rules_conf_t rules;
    ngx_uint_t   route_cache_size;
    ngx_uint_t   route_resolve;
    ngx_uint_t   route_drain;
    ngx_uint_t   route_enabled;
    ngx_stream_trojan_route_cache_t *route_cache;
    ngx_resolver_t *route_resolver;
    ngx_uint_t   route_internal_resolver;
    ngx_stream_core_srv_conf_t *core_srv_conf;
};


typedef struct ngx_stream_trojan_ctx_s ngx_stream_trojan_ctx_t;


typedef enum {
    ngx_stream_trojan_state_prefix = 0,
    ngx_stream_trojan_state_socks5_in_greeting,
    ngx_stream_trojan_state_socks5_in_request,
    ngx_stream_trojan_state_socks5_in_response,
    ngx_stream_trojan_state_socks5_in_udp_control,
    ngx_stream_trojan_state_http_in_request,
    ngx_stream_trojan_state_http_in_response,
    ngx_stream_trojan_state_request,
    ngx_stream_trojan_state_default_fallback,
    ngx_stream_trojan_state_resolving,
    ngx_stream_trojan_state_connecting,
    ngx_stream_trojan_state_socks5_tcp,
    ngx_stream_trojan_state_socks5_udp,
    ngx_stream_trojan_state_proxy,
    ngx_stream_trojan_state_udp
} ngx_stream_trojan_state_e;


typedef enum {
    ngx_stream_trojan_resolve_tcp = 0,
    ngx_stream_trojan_resolve_udp,
    ngx_stream_trojan_resolve_route,
    ngx_stream_trojan_resolve_udp_route
} ngx_stream_trojan_resolve_e;


typedef enum {
    ngx_stream_trojan_route_resume_none = 0,
    ngx_stream_trojan_route_resume_request,
    ngx_stream_trojan_route_resume_socks5_in,
    ngx_stream_trojan_route_resume_http_in
} ngx_stream_trojan_route_resume_e;


typedef struct {
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_resolve_e     type;
    ngx_stream_trojan_route_resume_e route_resume;
    ngx_uint_t                      ip_prefer;
    uint16_t                        port;
    uint16_t                        payload_len;
    u_char                         *payload;
    ngx_stream_trojan_addr_t        target;
} ngx_stream_trojan_resolve_data_t;


typedef struct {
    ngx_stream_trojan_srv_conf_t       *conf;
    ngx_stream_trojan_route_cache_t    *cache;
    ngx_stream_trojan_route_cache_entry_t *entry;
    ngx_uint_t                          generation;
    ngx_str_t                           name;
    ngx_stream_trojan_addr_t            target;
    ngx_log_t                          *log;
} ngx_stream_trojan_route_refresh_t;


typedef struct {
    ngx_resolver_addr_t      addrs[NGX_STREAM_TROJAN_ROUTE_MAX_SYSTEM_ADDRS];
    struct sockaddr_storage  sockaddr[NGX_STREAM_TROJAN_ROUTE_MAX_SYSTEM_ADDRS];
    ngx_uint_t               naddrs;
} ngx_stream_trojan_route_addrs_t;


typedef enum {
    ngx_stream_trojan_peer_none = 0,
    ngx_stream_trojan_peer_fallback,
    ngx_stream_trojan_peer_tcp
} ngx_stream_trojan_peer_e;


struct ngx_stream_trojan_ctx_s {
    ngx_stream_session_t       *session;
    ngx_stream_trojan_srv_conf_t *conf;

    ngx_stream_trojan_state_e   state;
    ngx_stream_trojan_peer_e    peer_kind;
    ngx_stream_trojan_outbound_t *outbound;

    u_char                      prefix[NGX_STREAM_TROJAN_PREFIX_LEN];
    size_t                      prefix_len;

    u_char                      request[1 + NGX_STREAM_TROJAN_MAX_ADDR_LEN + 2];
    size_t                      request_len;
    u_char                      command;
    ngx_stream_trojan_addr_t    target;
    ngx_stream_trojan_route_resume_e route_resume;
    ngx_queue_t                  route_queue;
    ngx_stream_trojan_route_cache_entry_t *route_entry;
    ngx_msec_t                   route_last_active;
    ngx_stream_trojan_outbound_t *route_tracked_outbound;
    unsigned                     route_linked:1;
    unsigned                     route_stale:1;

    ngx_peer_connection_t       peer;
    ngx_str_t                   peer_name;
    ngx_connection_t           *upstream;

    ngx_buf_t                  *client_buffer;
    ngx_buf_t                  *upstream_buffer;
    ngx_buf_t                  *pending_to_upstream;
    ngx_buf_t                  *pending_to_client;

    ngx_connection_t           *udp4;
#if (NGX_HAVE_INET6)
    ngx_connection_t           *udp6;
#endif
    ngx_connection_t           *socks5_udp;
    ngx_connection_t           *socks5_in_udp;
    ngx_stream_trojan_outbound_t *socks5_udp_outbound;
    ngx_addr_t                  socks5_udp_relay;
    struct sockaddr_storage     socks5_udp_client;
    socklen_t                   socks5_udp_client_socklen;
    ngx_uint_t                  socks5_udp_client_set;
    ngx_resolver_ctx_t         *resolver_ctx;
    u_char                     *udp_in;
    size_t                      udp_in_len;
    u_char                     *udp_out;
    u_char                     *udp_payload;
    ngx_buf_t                  *udp_pending_to_client;
    ngx_stream_trojan_addr_t    udp_route_addr;
    ngx_stream_trojan_outbound_t *udp_route_saved_outbound;
    ngx_stream_trojan_outbound_t *udp_route_restore_outbound;
    uint16_t                    udp_route_payload_len;
    ngx_uint_t                  udp_route_pending;
    ngx_stream_trojan_udp_route_mapping_t
                                *udp_route_mappings[NGX_STREAM_TROJAN_UDP_ROUTE_MAPPING_BUCKETS];

    ngx_buf_t                  *socks5_buffer;
    ngx_buf_t                  *http_buffer;
    ngx_stream_trojan_socks5_mode_e  socks5_mode;
    ngx_stream_trojan_socks5_step_e  socks5_step;
    ngx_uint_t                  socks5_connected;
    ngx_stream_trojan_in_socks5_step_e  in_socks5_step;
    ngx_stream_trojan_in_http_step_e  in_http_step;
    uint8_t                     socks5_in_status;
    uint16_t                    http_in_status;
    ngx_uint_t                  inbound_socks5;
    ngx_uint_t                  inbound_http_proxy;
    ngx_uint_t                  inbound_socks5_udp_enable;
};


static void ngx_stream_trojan_handler(ngx_stream_session_t *s);
static void ngx_stream_trojan_read_client(ngx_event_t *ev);
static void ngx_stream_trojan_peer_handler(ngx_event_t *ev);
static void ngx_stream_trojan_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_in_udp_read_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_udp_control_handler(ngx_event_t *ev);
static void ngx_stream_trojan_socks5_in_udp_control_handler(ngx_event_t *ev);
static void ngx_stream_trojan_udp_client_write_handler(ngx_event_t *ev);
static ngx_uint_t ngx_stream_trojan_client_buffered(
    ngx_stream_trojan_ctx_t *ctx, ngx_connection_t *c);
static ssize_t ngx_stream_trojan_recv(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *c, u_char *buf, size_t size);
static void ngx_stream_trojan_process_prefix(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_socks5_in(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_http_in(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_flush(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_http_in_flush(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_read(
    ngx_stream_trojan_ctx_t *ctx, size_t needed);
static ngx_int_t ngx_stream_trojan_http_in_read(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_prepare_method(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_in_prepare_response(
    ngx_stream_trojan_ctx_t *ctx, uint8_t status);
static ngx_int_t ngx_stream_trojan_http_in_prepare_response(
    ngx_stream_trojan_ctx_t *ctx, uint16_t status);
static ngx_int_t ngx_stream_trojan_init_udp_buffers(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_request(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_fallback(ngx_stream_trojan_ctx_t *ctx,
    u_char *data, size_t len);
static void ngx_stream_trojan_start_default_fallback(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_default_fallback_write_handler(
    ngx_event_t *ev);
static ngx_int_t ngx_stream_trojan_flush_default_fallback(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_tcp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_udp(ngx_stream_trojan_ctx_t *ctx);
static ngx_buf_t *ngx_stream_trojan_create_temp_buf(ngx_pool_t *pool,
    size_t size);
static ngx_int_t ngx_stream_trojan_set_pending(ngx_stream_trojan_ctx_t *ctx,
    u_char *data, size_t len);
static ngx_int_t ngx_stream_trojan_ensure_pending(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_socks5_tcp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_start_socks5_udp(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_close_socks5_udp(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_start_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_stream_trojan_resolve_e type,
    const u_char *payload, uint16_t payload_len, size_t wire_len);
static void ngx_stream_trojan_resolve_handler(ngx_resolver_ctx_t *rctx);
static void ngx_stream_trojan_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_addr_t *addr);
static void ngx_stream_trojan_socks5_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_socks5_mode_e mode);
static void ngx_stream_trojan_socks5_handler(ngx_event_t *ev);
static void ngx_stream_trojan_process_socks5(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_flush(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_read(ngx_stream_trojan_ctx_t *ctx,
    size_t needed);
static ngx_int_t ngx_stream_trojan_socks5_prepare_greeting(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_prepare_auth(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_prepare_request(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_socks5_response_to_ngx_addr(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *addr,
    ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_send_socks5_udp_frame(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_forward_socks5_udp_packet(
    ngx_stream_trojan_ctx_t *ctx, u_char *packet, size_t packet_len);
static ngx_int_t ngx_stream_trojan_select_outbound(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_stream_trojan_route_resume_e resume);
static void ngx_stream_trojan_request_after_route(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_socks5_in_after_route(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_http_in_after_route(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_route_resume(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_route_resume_e resume);
static void ngx_stream_trojan_route_resolve_target(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target);
static ngx_stream_trojan_outbound_t *ngx_stream_trojan_select_outbound_now(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs, ngx_uint_t lazy_used,
    ngx_uint_t *needs_resolve, ngx_uint_t *ttl_cache);
static ngx_uint_t ngx_stream_trojan_outbound_matches(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_outbound_t *outbound,
    ngx_stream_trojan_addr_t *target);
static ngx_uint_t ngx_stream_trojan_outbound_matches_domain(
    ngx_stream_trojan_outbound_t *outbound, ngx_stream_trojan_addr_t *target);
static ngx_uint_t ngx_stream_trojan_outbound_has_ip_rules(
    ngx_stream_trojan_outbound_t *outbound);
static ngx_uint_t ngx_stream_trojan_outbound_matches_resolved_ip(
    ngx_stream_trojan_outbound_t *outbound, ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs);
static ngx_int_t ngx_stream_trojan_start_route_resolver(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_stream_trojan_route_resume_e resume);
static ngx_int_t ngx_stream_trojan_start_udp_route_resolver(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_route_system_resolve(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_stream_trojan_route_addrs_t *resolved);
static ngx_uint_t ngx_stream_trojan_route_resolver_kind(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_resolver_t *ngx_stream_trojan_route_resolver(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_needs_internal_resolver(
    ngx_stream_trojan_srv_conf_t *tscf);
static ngx_int_t ngx_stream_trojan_create_internal_route_resolver(
    ngx_conf_t *cf, ngx_stream_trojan_srv_conf_t *tscf);
static ngx_int_t ngx_stream_trojan_read_system_nameservers(
    ngx_conf_t *cf, ngx_array_t *names);
static time_t ngx_stream_trojan_route_valid_time(ngx_resolver_ctx_t *rctx);
static void ngx_stream_trojan_route_refresh_handler(
    ngx_resolver_ctx_t *rctx);
static void ngx_stream_trojan_route_refresh_free(
    ngx_stream_trojan_route_refresh_t *refresh);
static void ngx_stream_trojan_route_cache_start_refresh(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_stream_trojan_route_cache_entry_t *entry);
static ngx_int_t ngx_stream_trojan_bind_outbound_matchers(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *tscf);
static ngx_int_t ngx_stream_trojan_route_cache_init(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *tscf);
static ngx_stream_trojan_route_cache_entry_t *
    ngx_stream_trojan_route_cache_lookup(
    ngx_stream_trojan_route_cache_t *cache, ngx_stream_trojan_addr_t *target);
static ngx_stream_trojan_route_cache_entry_t *
    ngx_stream_trojan_route_cache_insert(
    ngx_stream_trojan_route_cache_t *cache, ngx_stream_trojan_addr_t *target,
    ngx_stream_trojan_outbound_t *outbound, ngx_uint_t ttl, time_t expires);
static void ngx_stream_trojan_route_cache_update_entry(
    ngx_stream_trojan_route_cache_t *cache,
    ngx_stream_trojan_route_cache_entry_t *entry,
    ngx_stream_trojan_outbound_t *outbound, ngx_uint_t ttl, time_t expires);
static void ngx_stream_trojan_route_cache_unlink_active(
    ngx_stream_trojan_route_cache_entry_t *entry);
static void ngx_stream_trojan_route_mark_stale(
    ngx_stream_trojan_route_cache_entry_t *entry,
    ngx_stream_trojan_outbound_t *old_outbound);
static ngx_uint_t ngx_stream_trojan_route_fast_drain_enabled(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_route_track_tcp(
    ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_route_cache_entry_t *entry);
static void ngx_stream_trojan_route_untrack_tcp(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_route_touch_tcp(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_route_tcp_idle(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_route_check_tcp_stale(
    ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_route_track_udp(
    ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_route_mapping_t *mapping,
    ngx_stream_trojan_route_cache_entry_t *entry);
static void ngx_stream_trojan_route_untrack_udp(
    ngx_stream_trojan_udp_route_mapping_t *mapping);
static ngx_uint_t ngx_stream_trojan_route_cache_hash(
    ngx_stream_trojan_addr_t *target);
static ngx_stream_trojan_udp_route_mapping_t *
    ngx_stream_trojan_udp_route_mapping_lookup(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target);
static ngx_int_t ngx_stream_trojan_udp_route_mapping_insert(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *target,
    ngx_stream_trojan_outbound_t *outbound,
    ngx_stream_trojan_route_cache_entry_t *entry);
static ngx_uint_t ngx_stream_trojan_udp_route_mapping_hash(
    ngx_stream_trojan_addr_t *target);
static ngx_int_t ngx_stream_trojan_addr_equal(ngx_stream_trojan_addr_t *a,
    ngx_stream_trojan_addr_t *b);
static ngx_uint_t ngx_stream_trojan_outbound_type(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_current_block(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_request_blocked(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_uint_t ngx_stream_trojan_udp_frame_blocked(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_test_connect(ngx_connection_t *c);
static void ngx_stream_trojan_init_proxy(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_proxy(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_set_proxy_timeout(ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_process_direction(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src, ngx_connection_t *dst, ngx_buf_t *buf,
    ngx_uint_t *src_eof);
static ngx_int_t ngx_stream_trojan_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_resolve_addr(ngx_pool_t *pool,
    ngx_log_t *log, ngx_stream_trojan_addr_t *addr, ngx_addr_t *out);
static ngx_int_t ngx_stream_trojan_resolve_addr_prefer(ngx_pool_t *pool,
    ngx_log_t *log, ngx_stream_trojan_addr_t *addr, ngx_uint_t ip_prefer,
    ngx_addr_t *out);
static ngx_stream_core_srv_conf_t *ngx_stream_trojan_core_srv_conf(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_resolver_addr_t *ngx_stream_trojan_resolver_pick_addr(
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs, ngx_uint_t ip_prefer);
static ngx_int_t ngx_stream_trojan_resolver_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_resolver_addr_t *resolved, uint16_t port, ngx_addr_t *out);
static ngx_uint_t ngx_stream_trojan_current_ip_prefer(
    ngx_stream_trojan_ctx_t *ctx);
static ngx_int_t ngx_stream_trojan_parse_ip_prefer(ngx_str_t *value,
    ngx_uint_t *prefer);
static ngx_int_t ngx_stream_trojan_parse_block(ngx_str_t *value,
    ngx_uint_t *block);
static void ngx_stream_trojan_outbound_init(ngx_stream_trojan_outbound_t *outbound,
    ngx_uint_t type);
static ngx_int_t ngx_stream_trojan_outbound_set_tag(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, ngx_str_t *tag);
static ngx_int_t ngx_stream_trojan_parse_server_ref(ngx_conf_t *cf,
    ngx_str_t *value, ngx_stream_trojan_server_ref_t *ref);
static ngx_int_t ngx_stream_trojan_sockaddr_to_addr(struct sockaddr *sa,
    socklen_t socklen, ngx_stream_trojan_addr_t *addr);
static ngx_int_t ngx_stream_trojan_loopback_sockaddr(struct sockaddr *sa);
static ngx_int_t ngx_stream_trojan_local_proxy_check_listens(ngx_conf_t *cf,
    ngx_stream_core_srv_conf_t *cscf, ngx_stream_trojan_srv_conf_t *tscf);
static const char *ngx_stream_trojan_local_proxy_name(
    ngx_stream_trojan_srv_conf_t *tscf);
static ngx_stream_trojan_srv_conf_t *ngx_stream_trojan_local_proxy_conflict(
    ngx_stream_conf_addr_t *addr, ngx_stream_core_srv_conf_t *current);
static ngx_int_t ngx_stream_trojan_default_server_name(
    ngx_stream_core_srv_conf_t *cscf);
static ngx_stream_trojan_srv_conf_t *ngx_stream_trojan_find_trojan_server(
    ngx_conf_t *cf, ngx_stream_trojan_server_ref_t *ref, ngx_uint_t log_level);
static ngx_int_t ngx_stream_trojan_postconfiguration(ngx_conf_t *cf);
static ngx_connection_t *ngx_stream_trojan_create_udp_connection(
    ngx_stream_trojan_ctx_t *ctx, int family, ngx_event_handler_pt handler);
static ngx_connection_t *ngx_stream_trojan_create_bound_udp_connection(
    ngx_stream_trojan_ctx_t *ctx, int family,
    ngx_event_handler_pt handler);
static ngx_int_t ngx_stream_trojan_socks5_udp_bind_addr(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_addr_t *addr);
static ngx_int_t ngx_stream_trojan_send_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_send_udp_frame_routed(
    ngx_stream_trojan_ctx_t *ctx, ngx_stream_trojan_udp_frame_t *frame);
static ngx_int_t ngx_stream_trojan_send_udp_resolved(
    ngx_stream_trojan_ctx_t *ctx, ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs, uint16_t port, const u_char *payload,
    uint16_t payload_len, ngx_uint_t ip_prefer);
static ngx_int_t ngx_stream_trojan_send_udp_sockaddr(
    ngx_stream_trojan_ctx_t *ctx, struct sockaddr *sa, socklen_t socklen,
    const u_char *payload, uint16_t payload_len);
static ngx_int_t ngx_stream_trojan_flush_udp_client(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_process_udp_client(ngx_stream_trojan_ctx_t *ctx);
static void ngx_stream_trojan_finalize(ngx_stream_trojan_ctx_t *ctx,
    ngx_uint_t rc);

static void *ngx_stream_trojan_create_srv_conf(ngx_conf_t *cf);
static char *ngx_stream_trojan_merge_srv_conf(ngx_conf_t *cf, void *parent,
    void *child);
static char *ngx_stream_trojan_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_socks5_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_http_proxy_on(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_socks5_udp_on(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_trojan_server(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_password(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_fallback(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_outbounds(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
static char *ngx_stream_trojan_outbound_direct_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_outbound_socks5_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_outbounds_block(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_route_cache(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_route_resolve(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);
static char *ngx_stream_trojan_route_drain(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf);


static ngx_command_t ngx_stream_trojan_commands[] = {

    { ngx_string("trojan"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, enable),
      NULL },

    { ngx_string("socks5"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_socks5_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, socks5_enable),
      NULL },

    { ngx_string("http_proxy"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_http_proxy_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, http_proxy_enable),
      NULL },

    { ngx_string("socks5_udp"),
      NGX_STREAM_SRV_CONF|NGX_CONF_FLAG,
      ngx_stream_trojan_socks5_udp_on,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, socks5_udp_enable),
      NULL },

    { ngx_string("trojan_server"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_trojan_server,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_password"),
      NGX_STREAM_SRV_CONF|NGX_CONF_1MORE,
      ngx_stream_trojan_password,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_fallback"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_fallback,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("trojan_connect_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, connect_timeout),
      NULL },

    { ngx_string("trojan_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, timeout),
      NULL },

    { ngx_string("trojan_udp_timeout"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_msec_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, udp_timeout),
      NULL },

    { ngx_string("trojan_buffer_size"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_size_slot,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, buffer_size),
      NULL },

    { ngx_string("outbounds"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_trojan_outbounds,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("outbounds_direct"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_stream_trojan_outbound_direct_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("outbounds_socks5"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_NOARGS|NGX_CONF_TAKE1,
      ngx_stream_trojan_outbound_socks5_directive,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("route_rules"),
      NGX_STREAM_MAIN_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_trojan_route_rules_block,
      NGX_STREAM_MAIN_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("route_rules"),
      NGX_STREAM_SRV_CONF|NGX_CONF_BLOCK|NGX_CONF_TAKE1,
      ngx_stream_trojan_route_rules_block,
      NGX_STREAM_SRV_CONF_OFFSET,
      offsetof(ngx_stream_trojan_srv_conf_t, rules),
      NULL },

    { ngx_string("route_cache"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_route_cache,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("route_resolve"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_route_resolve,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("route_drain"),
      NGX_STREAM_SRV_CONF|NGX_CONF_TAKE1,
      ngx_stream_trojan_route_drain,
      NGX_STREAM_SRV_CONF_OFFSET,
      0,
      NULL },

      ngx_null_command
};


static ngx_stream_module_t ngx_stream_trojan_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_stream_trojan_postconfiguration,   /* postconfiguration */
    ngx_stream_trojan_create_main_conf,    /* create main configuration */
    NULL,                                  /* init main configuration */
    ngx_stream_trojan_create_srv_conf,     /* create server configuration */
    ngx_stream_trojan_merge_srv_conf       /* merge server configuration */
};


ngx_module_t ngx_stream_trojan_module = {
    NGX_MODULE_V1,
    &ngx_stream_trojan_module_ctx,
    ngx_stream_trojan_commands,
    NGX_STREAM_MODULE,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NULL,
    NGX_MODULE_V1_PADDING
};


static void
ngx_stream_trojan_handler(ngx_stream_session_t *s)
{
    ngx_connection_t              *c;
    ngx_stream_trojan_ctx_t       *ctx;
    ngx_stream_trojan_srv_conf_t  *tscf;

    c = s->connection;
    tscf = ngx_stream_get_module_srv_conf(s, ngx_stream_trojan_module);

    if (!tscf->enable && !tscf->socks5_enable && !tscf->http_proxy_enable) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx = ngx_pcalloc(c->pool, sizeof(ngx_stream_trojan_ctx_t));
    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->session = s;
    ctx->conf = tscf;
    ctx->state = ngx_stream_trojan_state_prefix;
    ngx_queue_init(&ctx->route_queue);

    ngx_stream_set_ctx(s, ctx, ngx_stream_trojan_module);

    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;

    if ((tscf->socks5_enable || tscf->http_proxy_enable) && !tscf->enable) {
        ctx->inbound_socks5 = tscf->socks5_enable ? 1 : 0;
        ctx->inbound_http_proxy = tscf->http_proxy_enable ? 1 : 0;
        ctx->inbound_socks5_udp_enable = tscf->socks5_udp_enable ? 1 : 0;
        if (ctx->inbound_socks5) {
            ctx->state = ngx_stream_trojan_state_socks5_in_greeting;
            ngx_stream_trojan_process_socks5_in(ctx);
            return;
        }

        ctx->state = ngx_stream_trojan_state_http_in_request;
        ngx_stream_trojan_process_http_in(ctx);
        return;
    }

    ngx_stream_trojan_process_prefix(ctx);
}


static void
ngx_stream_trojan_read_client(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ev->timedout) {
        if (ctx->route_stale) {
            if (ngx_stream_trojan_route_check_tcp_stale(ctx)) {
                return;
            }

            ev->timedout = 0;
            ngx_add_timer(c->read, NGX_STREAM_TROJAN_ROUTE_DRAIN_TIMEOUT);
            return;
        }

        ngx_connection_error(c, NGX_ETIMEDOUT, "trojan client timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    switch (ctx->state) {
    case ngx_stream_trojan_state_socks5_in_greeting:
    case ngx_stream_trojan_state_socks5_in_request:
    case ngx_stream_trojan_state_socks5_in_response:
        ngx_stream_trojan_process_socks5_in(ctx);
        break;

    case ngx_stream_trojan_state_http_in_request:
    case ngx_stream_trojan_state_http_in_response:
        ngx_stream_trojan_process_http_in(ctx);
        break;

    case ngx_stream_trojan_state_prefix:
        ngx_stream_trojan_process_prefix(ctx);
        break;

    case ngx_stream_trojan_state_request:
        ngx_stream_trojan_process_request(ctx);
        break;

    case ngx_stream_trojan_state_default_fallback:
        ngx_stream_trojan_default_fallback_write_handler(c->write);
        break;

    case ngx_stream_trojan_state_resolving:
    case ngx_stream_trojan_state_socks5_tcp:
    case ngx_stream_trojan_state_socks5_udp:
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        }
        break;

    case ngx_stream_trojan_state_proxy:
        ngx_stream_trojan_process_proxy(ctx);
        break;

    case ngx_stream_trojan_state_udp:
        ngx_stream_trojan_process_udp_client(ctx);
        break;

    default:
        break;
    }
}


static ngx_int_t
ngx_stream_trojan_key_valid(ngx_stream_trojan_srv_conf_t *tscf, u_char *key)
{
    ngx_uint_t                i;
    ngx_stream_trojan_key_t  *keys;

    keys = tscf->keys->elts;

    for (i = 0; i < tscf->keys->nelts; i++) {
        if (ngx_stream_trojan_key_equal(key, keys[i].data)) {
            return NGX_OK;
        }
    }

    return NGX_DECLINED;
}


static void
ngx_stream_trojan_process_socks5_in(ngx_stream_trojan_ctx_t *ctx)
{
    int                         rc;
    size_t                      needed;
    uint8_t                     method, command;
    ngx_stream_trojan_srv_conf_t *effective, *socks5_conf;

    if (ctx->socks5_buffer == NULL) {
        ctx->socks5_buffer = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
        if (ctx->socks5_buffer == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    for ( ;; ) {
        switch (ctx->state) {

        case ngx_stream_trojan_state_socks5_in_greeting:
            rc = ngx_stream_trojan_socks5_greeting_len(
                ctx->socks5_buffer->pos,
                ctx->socks5_buffer->last - ctx->socks5_buffer->pos,
                &needed);

            if (rc != 0
                && ctx->inbound_http_proxy
                && ctx->socks5_buffer->last > ctx->socks5_buffer->pos
                && ctx->socks5_buffer->pos[0]
                   != NGX_STREAM_TROJAN_SOCKS5_VERSION)
            {
                if (!ngx_stream_trojan_http_proxy_looks_like_http(
                        ctx->socks5_buffer->pos,
                        ctx->socks5_buffer->last - ctx->socks5_buffer->pos))
                {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                ctx->http_buffer = ctx->socks5_buffer;
                ctx->socks5_buffer = NULL;
                ctx->state = ngx_stream_trojan_state_http_in_request;
                ngx_stream_trojan_process_http_in(ctx);
                return;
            }

            if (rc == 1) {
                rc = ngx_stream_trojan_socks5_in_read(ctx, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                continue;
            }

            if (rc != 0) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                return;
            }

            method = ngx_stream_trojan_socks5_select_method(
                ctx->socks5_buffer->pos,
                ctx->socks5_buffer->last - ctx->socks5_buffer->pos);

            if (ngx_stream_trojan_socks5_in_prepare_method(ctx)
                != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (method != NGX_STREAM_TROJAN_SOCKS5_METHOD_NO_AUTH) {
                ctx->socks5_buffer->start[1] =
                    NGX_STREAM_TROJAN_SOCKS5_METHOD_NONE;
                ctx->state = ngx_stream_trojan_state_socks5_in_response;
                continue;
            }

            ctx->state = ngx_stream_trojan_state_socks5_in_response;
            ctx->in_socks5_step = ngx_stream_trojan_in_socks5_step_method_write;
            continue;

        case ngx_stream_trojan_state_socks5_in_response:
            rc = ngx_stream_trojan_socks5_in_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ctx->in_socks5_step
                == ngx_stream_trojan_in_socks5_step_response_write)
            {
                if (ctx->socks5_in_status
                    != NGX_STREAM_TROJAN_SOCKS5_STATUS_OK)
                {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
                    return;
                }

                if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT) {
                    ngx_stream_trojan_start_tcp(ctx);
                    return;
                }

                if (ngx_stream_trojan_outbound_type(ctx)
                    == ngx_stream_trojan_outbound_socks5)
                {
                    ngx_stream_trojan_start_socks5_udp(ctx);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
                ctx->session->connection->read->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ctx->session->connection->write->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ngx_add_timer(ctx->session->connection->read,
                              ctx->conf->udp_timeout);
                if (ngx_handle_read_event(ctx->session->connection->read, 0)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                return;
            }

            if (ctx->socks5_buffer->start[1]
                == NGX_STREAM_TROJAN_SOCKS5_METHOD_NONE)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
                return;
            }

            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            ctx->state = ngx_stream_trojan_state_socks5_in_request;
            continue;

        case ngx_stream_trojan_state_socks5_in_request:
            rc = ngx_stream_trojan_socks5_request_len(
                ctx->socks5_buffer->pos,
                ctx->socks5_buffer->last - ctx->socks5_buffer->pos,
                &needed);

            if (rc == 1) {
                rc = ngx_stream_trojan_socks5_in_read(ctx, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                continue;
            }

            if (rc != 0
                || ngx_stream_trojan_socks5_parse_request(
                       ctx->socks5_buffer->pos,
                       ctx->socks5_buffer->last - ctx->socks5_buffer->pos,
                       &command, &ctx->target)
                   != 0)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                return;
            }

            socks5_conf = ctx->conf;
            effective = socks5_conf->effective;
            if (effective == NULL) {
                if (ngx_stream_trojan_socks5_in_prepare_response(
                        ctx, NGX_STREAM_TROJAN_SOCKS5_STATUS_GENERAL_FAILURE)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_socks5_in_response;
                ctx->in_socks5_step =
                    ngx_stream_trojan_in_socks5_step_response_write;
                continue;
            }

            ctx->command = command == NGX_STREAM_TROJAN_SOCKS5_CMD_CONNECT
                           ? NGX_STREAM_TROJAN_CMD_CONNECT
                           : NGX_STREAM_TROJAN_CMD_ASSOCIATE;
            ctx->conf = effective;

            rc = ngx_stream_trojan_select_outbound(
                ctx, &ctx->target, ngx_stream_trojan_route_resume_socks5_in);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ngx_stream_trojan_socks5_in_after_route(ctx);
            continue;

        default:
            return;
        }
    }
}


static void
ngx_stream_trojan_process_http_in(ngx_stream_trojan_ctx_t *ctx)
{
    int                          rc;
    size_t                       needed;
    ngx_stream_trojan_srv_conf_t *effective, *proxy_conf;

    if (ctx->http_buffer == NULL) {
        ctx->http_buffer = ngx_stream_trojan_create_temp_buf(
            ctx->session->connection->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
        if (ctx->http_buffer == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }
    }

    for ( ;; ) {
        switch (ctx->state) {

        case ngx_stream_trojan_state_http_in_request:
            rc = ngx_stream_trojan_http_proxy_parse_connect(
                ctx->http_buffer->pos,
                ctx->http_buffer->last - ctx->http_buffer->pos,
                &needed, &ctx->target);

            if (rc == NGX_STREAM_TROJAN_HTTP_PROXY_NEED_MORE) {
                rc = ngx_stream_trojan_http_in_read(ctx);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
                    return;
                }

                continue;
            }

            if (rc != NGX_STREAM_TROJAN_HTTP_PROXY_OK) {
                if (ngx_stream_trojan_http_in_prepare_response(
                        ctx,
                        rc == NGX_STREAM_TROJAN_HTTP_PROXY_METHOD_NOT_ALLOWED
                        ? 405 : 400)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_http_in_response;
                ctx->in_http_step =
                    ngx_stream_trojan_in_http_step_response_write;
                continue;
            }

            proxy_conf = ctx->conf;
            effective = proxy_conf->effective;
            if (effective == NULL) {
                if (ngx_stream_trojan_http_in_prepare_response(ctx, 502)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->state = ngx_stream_trojan_state_http_in_response;
                ctx->in_http_step =
                    ngx_stream_trojan_in_http_step_response_write;
                continue;
            }

            ctx->command = NGX_STREAM_TROJAN_CMD_CONNECT;
            ctx->conf = effective;

            if (ctx->http_buffer->last > ctx->http_buffer->pos + needed
                && ngx_stream_trojan_set_pending(
                       ctx, ctx->http_buffer->pos + needed,
                       ctx->http_buffer->last - (ctx->http_buffer->pos + needed))
                   != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            rc = ngx_stream_trojan_select_outbound(
                ctx, &ctx->target, ngx_stream_trojan_route_resume_http_in);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ngx_stream_trojan_http_in_after_route(ctx);
            continue;

        case ngx_stream_trojan_state_http_in_response:
            rc = ngx_stream_trojan_http_in_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ctx->http_in_status != 200) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
                return;
            }

            ngx_stream_trojan_start_tcp(ctx);
            return;

        default:
            return;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_http_in_flush(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->http_buffer;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_http_in_read(ngx_stream_trojan_ctx_t *ctx)
{
    size_t             available;
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->http_buffer;

    if (b->last == b->end) {
        return NGX_ERROR;
    }

    available = b->end - b->last;
    n = ngx_stream_trojan_recv(ctx, c, b->last, available);

    if (n == NGX_AGAIN) {
        if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
            return NGX_ERROR;
        }
        return NGX_AGAIN;
    }

    if (n == 0 || n == NGX_ERROR) {
        return NGX_ERROR;
    }

    b->last += n;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_http_in_prepare_response(ngx_stream_trojan_ctx_t *ctx,
    uint16_t status)
{
    size_t      written;
    ngx_buf_t  *b;

    ctx->http_in_status = status;

    b = ctx->http_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_http_proxy_build_response(
            status, b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_flush(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->socks5_buffer;

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_read(ngx_stream_trojan_ctx_t *ctx, size_t needed)
{
    size_t             available;
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->socks5_buffer;

    if (needed > (size_t) (b->end - b->start)) {
        return NGX_ERROR;
    }

    while ((size_t) (b->last - b->pos) < needed) {
        available = needed - (size_t) (b->last - b->pos);
        n = ngx_stream_trojan_recv(ctx, c, b->last, available);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->last += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_prepare_method(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_buf_t  *b;

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start + 2;

    return ngx_stream_trojan_socks5_build_method_response(
        NGX_STREAM_TROJAN_SOCKS5_METHOD_NO_AUTH, b->pos, 2)
        == 0 ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_socks5_in_prepare_response(ngx_stream_trojan_ctx_t *ctx,
    uint8_t status)
{
    size_t                      written;
    ngx_buf_t                  *b;
    ngx_stream_trojan_addr_t    bind_addr;
    u_char                      zero[4] = { 0, 0, 0, 0 };

    ctx->socks5_in_status = status;

    ngx_memzero(&bind_addr, sizeof(bind_addr));
    if (status == NGX_STREAM_TROJAN_SOCKS5_STATUS_OK
        && ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE)
    {
        if (ngx_stream_trojan_socks5_udp_bind_addr(ctx, &bind_addr)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

    } else {
        bind_addr.type = NGX_STREAM_TROJAN_ADDR_IPV4;
        bind_addr.host_len = 4;
        ngx_memcpy(bind_addr.host, zero, 4);
        bind_addr.port = 0;
        bind_addr.wire_len = 1 + 4 + 2;
    }

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_socks5_build_response(status, &bind_addr,
                                                b->last, b->end - b->last,
                                                &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_init_udp_buffers(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_pool_t  *pool;

    pool = ctx->session->connection->pool;

    if (ctx->udp_in == NULL) {
        ctx->udp_in = ngx_pnalloc(pool, NGX_STREAM_TROJAN_UDP_BUFFER_SIZE);
        if (ctx->udp_in == NULL) {
            return NGX_ERROR;
        }
    }

    if (ctx->udp_out == NULL) {
        ctx->udp_out = ngx_pnalloc(pool, NGX_STREAM_TROJAN_UDP_BUFFER_SIZE);
        if (ctx->udp_out == NULL) {
            return NGX_ERROR;
        }
    }

    if (ctx->udp_payload == NULL) {
        ctx->udp_payload = ngx_pnalloc(pool,
                                       NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD);
        if (ctx->udp_payload == NULL) {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static ngx_uint_t
ngx_stream_trojan_client_buffered(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *c)
{
    ngx_buf_t  *b;

    if (c != ctx->session->connection) {
        return 0;
    }

    b = c->buffer;

    return b != NULL && b->pos < b->last;
}


static ssize_t
ngx_stream_trojan_recv(ngx_stream_trojan_ctx_t *ctx, ngx_connection_t *c,
    u_char *buf, size_t size)
{
    size_t      n;
    ngx_buf_t  *b;

    if (!ngx_stream_trojan_client_buffered(ctx, c)) {
        return c->recv(c, buf, size);
    }

    /* SSL preread consumes decrypted data into the stream core buffer. */
    b = c->buffer;
    n = ngx_min(size, (size_t) (b->last - b->pos));

    ngx_memcpy(buf, b->pos, n);
    b->pos += n;

    return (ssize_t) n;
}


static void
ngx_stream_trojan_process_prefix(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    size_t             i;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    for ( ;; ) {
        if (ctx->prefix_len == NGX_STREAM_TROJAN_PREFIX_LEN) {
            break;
        }

        n = ngx_stream_trojan_recv(
            ctx, c, ctx->prefix + ctx->prefix_len,
            NGX_STREAM_TROJAN_PREFIX_LEN - ctx->prefix_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        for (i = ctx->prefix_len; i < ctx->prefix_len + (size_t) n; i++) {
            if (ctx->prefix[i] == LF && i < NGX_STREAM_TROJAN_KEY_LEN + 1) {
                ctx->prefix_len += (size_t) n;
                ngx_stream_trojan_start_fallback(ctx, ctx->prefix,
                                                 ctx->prefix_len);
                return;
            }
        }

        ctx->prefix_len += (size_t) n;
    }

    if (ctx->prefix[NGX_STREAM_TROJAN_KEY_LEN] != CR
        || ctx->prefix[NGX_STREAM_TROJAN_KEY_LEN + 1] != LF
        || ngx_stream_trojan_key_valid(ctx->conf, ctx->prefix) != NGX_OK)
    {
        ngx_stream_trojan_start_fallback(ctx, ctx->prefix, ctx->prefix_len);
        return;
    }

    ctx->state = ngx_stream_trojan_state_request;
    ngx_stream_trojan_process_request(ctx);
}


static ngx_int_t
ngx_stream_trojan_request_needed(u_char *buf, size_t len, size_t *needed)
{
    size_t addr_len;

    if (len < 2) {
        *needed = 2;
        return NGX_AGAIN;
    }

    if (buf[0] != NGX_STREAM_TROJAN_CMD_CONNECT
        && buf[0] != NGX_STREAM_TROJAN_CMD_ASSOCIATE)
    {
        return NGX_ERROR;
    }

    switch (buf[1]) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        addr_len = 1 + 4 + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (len < 3) {
            *needed = 3;
            return NGX_AGAIN;
        }
        addr_len = 1 + 1 + buf[2] + 2;
        break;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        addr_len = 1 + 16 + 2;
        break;

    default:
        return NGX_ERROR;
    }

    *needed = 1 + addr_len + 2;

    if (len < *needed) {
        return NGX_AGAIN;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_process_request(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    size_t             needed;
    ngx_int_t          rc;
    ngx_connection_t  *c;

    c = ctx->session->connection;

    for ( ;; ) {
        rc = ngx_stream_trojan_request_needed(ctx->request, ctx->request_len,
                                              &needed);

        if (rc == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        if (rc == NGX_OK) {
            break;
        }

        if (needed > sizeof(ctx->request)) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        n = ngx_stream_trojan_recv(ctx, c,
                                   ctx->request + ctx->request_len,
                                   needed - ctx->request_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ctx->request_len += (size_t) n;
    }

    if (ctx->request[needed - 2] != CR || ctx->request[needed - 1] != LF) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    if (ngx_stream_trojan_parse_addr(ctx->request + 1, needed - 3,
                                     &ctx->target)
        != 0)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
        return;
    }

    ctx->command = ctx->request[0];
    rc = ngx_stream_trojan_select_outbound(
        ctx, &ctx->target, ngx_stream_trojan_route_resume_request);
    if (rc == NGX_AGAIN) {
        return;
    }

    if (rc != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_stream_trojan_request_after_route(ctx);
}


static void
ngx_stream_trojan_request_after_route(ngx_stream_trojan_ctx_t *ctx)
{
    if (ngx_stream_trojan_request_blocked(ctx)) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_FORBIDDEN);
        return;
    }

    if (ctx->command == NGX_STREAM_TROJAN_CMD_CONNECT) {
        ngx_stream_trojan_start_tcp(ctx);
        return;
    }

    ngx_stream_trojan_start_udp(ctx);
}


static void
ngx_stream_trojan_socks5_in_after_route(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
        && !ctx->inbound_socks5_udp_enable)
    {
        if (ngx_stream_trojan_socks5_in_prepare_response(ctx, 0x07)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->state = ngx_stream_trojan_state_socks5_in_response;
        ctx->in_socks5_step =
            ngx_stream_trojan_in_socks5_step_response_write;
        return;
    }

    if (ngx_stream_trojan_request_blocked(ctx)) {
        if (ngx_stream_trojan_socks5_in_prepare_response(ctx, 0x02)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->state = ngx_stream_trojan_state_socks5_in_response;
        ctx->in_socks5_step =
            ngx_stream_trojan_in_socks5_step_response_write;
        return;
    }

    if (ctx->command == NGX_STREAM_TROJAN_CMD_ASSOCIATE
        && ngx_stream_trojan_init_udp_buffers(ctx) != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_stream_trojan_socks5_in_prepare_response(
            ctx, NGX_STREAM_TROJAN_SOCKS5_STATUS_OK)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state = ngx_stream_trojan_state_socks5_in_response;
    ctx->in_socks5_step = ngx_stream_trojan_in_socks5_step_response_write;
}


static void
ngx_stream_trojan_http_in_after_route(ngx_stream_trojan_ctx_t *ctx)
{
    if (ngx_stream_trojan_request_blocked(ctx)) {
        if (ngx_stream_trojan_http_in_prepare_response(ctx, 403) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->state = ngx_stream_trojan_state_http_in_response;
        ctx->in_http_step = ngx_stream_trojan_in_http_step_response_write;
        return;
    }

    if (ngx_stream_trojan_http_in_prepare_response(ctx, 200) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->state = ngx_stream_trojan_state_http_in_response;
    ctx->in_http_step = ngx_stream_trojan_in_http_step_response_write;
}


static void
ngx_stream_trojan_route_resume(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_route_resume_e resume)
{
    ctx->route_resume = ngx_stream_trojan_route_resume_none;

    switch (resume) {
    case ngx_stream_trojan_route_resume_request:
        ngx_stream_trojan_request_after_route(ctx);
        return;

    case ngx_stream_trojan_route_resume_socks5_in:
        ngx_stream_trojan_socks5_in_after_route(ctx);
        if (ctx->state == ngx_stream_trojan_state_socks5_in_response) {
            ngx_stream_trojan_process_socks5_in(ctx);
        }
        return;

    case ngx_stream_trojan_route_resume_http_in:
        ngx_stream_trojan_http_in_after_route(ctx);
        if (ctx->state == ngx_stream_trojan_state_http_in_response) {
            ngx_stream_trojan_process_http_in(ctx);
        }
        return;

    default:
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }
}


static ngx_buf_t *
ngx_stream_trojan_create_temp_buf(ngx_pool_t *pool, size_t size)
{
    ngx_buf_t  *b;

    b = ngx_create_temp_buf(pool, size);
    if (b == NULL) {
        return NULL;
    }

    b->tag = (ngx_buf_tag_t) &ngx_stream_trojan_module;
    return b;
}


static ngx_int_t
ngx_stream_trojan_set_pending(ngx_stream_trojan_ctx_t *ctx, u_char *data,
    size_t len)
{
    ctx->pending_to_upstream = ngx_stream_trojan_create_temp_buf(
        ctx->session->connection->pool, len ? len : 1);

    if (ctx->pending_to_upstream == NULL) {
        return NGX_ERROR;
    }

    if (len) {
        ngx_memcpy(ctx->pending_to_upstream->last, data, len);
        ctx->pending_to_upstream->last += len;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_ensure_pending(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->pending_to_upstream != NULL) {
        return NGX_OK;
    }

    return ngx_stream_trojan_set_pending(ctx, NULL, 0);
}


static void
ngx_stream_trojan_start_fallback(ngx_stream_trojan_ctx_t *ctx, u_char *data,
    size_t len)
{
    if (ctx->conf->fallback == NULL) {
        ngx_stream_trojan_start_default_fallback(ctx);
        return;
    }

    if (ngx_stream_trojan_set_pending(ctx, data, len) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_fallback;
    ngx_stream_trojan_connect(ctx, ctx->conf->fallback);
}


static void
ngx_stream_trojan_start_default_fallback(ngx_stream_trojan_ctx_t *ctx)
{
    size_t         len;
    const u_char  *response;
    ngx_connection_t *c;

    c = ctx->session->connection;
    response = ngx_stream_trojan_default_fallback_response(&len);

    ctx->pending_to_client = ngx_stream_trojan_create_temp_buf(c->pool, len);
    if (ctx->pending_to_client == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memcpy(ctx->pending_to_client->last, response, len);
    ctx->pending_to_client->last += len;

    ctx->state = ngx_stream_trojan_state_default_fallback;
    c->write->handler = ngx_stream_trojan_default_fallback_write_handler;
    c->read->handler = ngx_stream_trojan_default_fallback_write_handler;

    ngx_stream_trojan_default_fallback_write_handler(c->write);
}


static void
ngx_stream_trojan_default_fallback_write_handler(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL || ev->timedout) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    switch (ngx_stream_trojan_flush_default_fallback(ctx)) {
    case NGX_OK:
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;

    case NGX_AGAIN:
        return;

    default:
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }
}


static ngx_int_t
ngx_stream_trojan_flush_default_fallback(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->pending_to_client;

    while (b != NULL && b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_start_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_addr_t  addr;

    if (ngx_stream_trojan_outbound_type(ctx)
        == ngx_stream_trojan_outbound_socks5)
    {
        ngx_stream_trojan_start_socks5_tcp(ctx);
        return;
    }

    if (ngx_stream_trojan_use_nginx_resolver(
            ctx->target.type,
            ngx_stream_trojan_route_resolver(ctx) != NULL))
    {
        if (ngx_stream_trojan_ensure_pending(ctx) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ctx->peer_kind = ngx_stream_trojan_peer_tcp;
        if (ngx_stream_trojan_start_resolver(ctx, &ctx->target,
                                             ngx_stream_trojan_resolve_tcp,
                                             NULL, 0, 0)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        }
        return;
    }

    if (ngx_stream_trojan_resolve_addr_prefer(ctx->session->connection->pool,
                                              ctx->session->connection->log,
                                              &ctx->target,
                                              ngx_stream_trojan_current_ip_prefer(ctx),
                                              &addr)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_ensure_pending(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_tcp;
    ngx_stream_trojan_connect(ctx, &addr);
}


static void
ngx_stream_trojan_start_udp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ngx_stream_trojan_init_udp_buffers(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_stream_trojan_outbound_type(ctx)
        == ngx_stream_trojan_outbound_socks5)
    {
        ngx_stream_trojan_start_socks5_udp(ctx);
        return;
    }

    ctx->state = ngx_stream_trojan_state_udp;
    ctx->session->connection->write->handler =
        ngx_stream_trojan_udp_client_write_handler;
    ngx_add_timer(ctx->session->connection->read, ctx->conf->udp_timeout);
    ngx_stream_trojan_process_udp_client(ctx);
}


static ngx_int_t
ngx_stream_trojan_start_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_stream_trojan_resolve_e type,
    const u_char *payload, uint16_t payload_len, size_t wire_len)
{
    ngx_str_t                         name;
    ngx_pool_t                       *pool;
    ngx_resolver_ctx_t               *rctx, temp;
    ngx_resolver_t                   *resolver;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_trojan_resolve_data_t *data;

    if (addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || addr->host_len == 0 || addr->host_len > 255)
    {
        return NGX_ERROR;
    }

    pool = ctx->session->connection->pool;

    data = ngx_pcalloc(pool, sizeof(ngx_stream_trojan_resolve_data_t));
    if (data == NULL) {
        return NGX_ERROR;
    }

    name.data = ngx_pnalloc(pool, addr->host_len);
    if (name.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(name.data, addr->host, addr->host_len);
    name.len = addr->host_len;

    if (payload_len) {
        data->payload = ngx_pnalloc(pool, payload_len);
        if (data->payload == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(data->payload, payload, payload_len);
    }

    data->ctx = ctx;
    data->type = type;
    data->route_resume = ctx->route_resume;
    data->ip_prefer = ngx_stream_trojan_current_ip_prefer(ctx);
    data->port = addr->port;
    data->payload_len = payload_len;
    data->target = *addr;

    ngx_memzero(&temp, sizeof(ngx_resolver_ctx_t));
    temp.name = name;

    resolver = ngx_stream_trojan_route_resolver(ctx);
    if (resolver == NULL) {
        return NGX_ERROR;
    }

    cscf = ngx_stream_trojan_core_srv_conf(ctx);
    if (cscf == NULL) {
        return NGX_ERROR;
    }

    rctx = ngx_resolve_start(resolver, &temp);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        return NGX_ERROR;
    }

    rctx->name = name;
    rctx->handler = ngx_stream_trojan_resolve_handler;
    rctx->data = data;
    rctx->timeout = cscf->resolver_timeout;

    ctx->resolver_ctx = rctx;
    ctx->state = ngx_stream_trojan_state_resolving;

    if ((type == ngx_stream_trojan_resolve_udp
         || type == ngx_stream_trojan_resolve_udp_route)
        && wire_len <= ctx->udp_in_len)
    {
        if (wire_len < ctx->udp_in_len) {
            ngx_memmove(ctx->udp_in, ctx->udp_in + wire_len,
                        ctx->udp_in_len - wire_len);
        }
        ctx->udp_in_len -= wire_len;
    }

    if (ngx_resolve_name(rctx) != NGX_OK) {
        ctx->resolver_ctx = NULL;
        return NGX_ERROR;
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_resolve_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_addr_t                         addr;
    ngx_int_t                          rc;
    ngx_uint_t                         ttl_cache;
    ngx_stream_trojan_ctx_t           *ctx;
    ngx_stream_trojan_outbound_t      *saved_outbound;
    ngx_stream_trojan_outbound_t      *outbound;
    ngx_stream_trojan_route_cache_entry_t *cached;
    ngx_stream_trojan_resolve_data_t  *data;
    ngx_stream_trojan_udp_frame_t      frame;

    data = rctx->data;
    ctx = data->ctx;

    if (ctx == NULL) {
        ngx_resolve_name_done(rctx);
        return;
    }

    ctx->resolver_ctx = NULL;

    if (rctx->state) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log, 0,
                      "%V could not be resolved (%i: %s)",
                      &rctx->name, rctx->state,
                      ngx_resolver_strerror(rctx->state));
        ngx_resolve_name_done(rctx);
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (data->type == ngx_stream_trojan_resolve_route) {
        ttl_cache = 0;
        outbound = ngx_stream_trojan_select_outbound_now(
            ctx, &data->target, rctx->addrs, rctx->naddrs, 1, NULL,
            &ttl_cache);
        if (outbound == NULL) {
            ngx_resolve_name_done(rctx);
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ctx->outbound = outbound;
        ctx->route_entry = ngx_stream_trojan_route_cache_insert(
            ctx->conf->route_cache, &data->target, outbound, ttl_cache,
            ngx_stream_trojan_route_valid_time(rctx));

        ngx_resolve_name_done(rctx);
        ngx_stream_trojan_route_resume(ctx, data->route_resume);
        return;
    }

    if (data->type == ngx_stream_trojan_resolve_udp_route) {
        ttl_cache = 0;
        outbound = ngx_stream_trojan_select_outbound_now(
            ctx, &data->target, rctx->addrs, rctx->naddrs, 1, NULL,
            &ttl_cache);
        if (outbound == NULL) {
            ngx_resolve_name_done(rctx);
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        saved_outbound = ctx->outbound;
        ctx->outbound = outbound;
        cached = ngx_stream_trojan_route_cache_insert(
            ctx->conf->route_cache, &data->target, outbound, ttl_cache,
            ngx_stream_trojan_route_valid_time(rctx));
        (void) ngx_stream_trojan_udp_route_mapping_insert(ctx, &data->target,
                                                          outbound, cached);

        frame.addr = data->target;
        frame.payload = data->payload;
        frame.payload_len = data->payload_len;
        frame.wire_len = 0;

        ctx->udp_route_restore_outbound = saved_outbound;

        if (ngx_stream_trojan_udp_frame_blocked(ctx, &frame)) {
            ctx->outbound = saved_outbound;
            ctx->udp_route_restore_outbound = NULL;
            ngx_resolve_name_done(rctx);
            if (ctx->inbound_socks5) {
                ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
                return;
            }

            ctx->state = ngx_stream_trojan_state_udp;
            ngx_stream_trojan_process_udp_client(ctx);
            return;
        }

        rc = ngx_stream_trojan_send_udp_frame_routed(ctx, &frame);
        if (rc == NGX_AGAIN) {
            ngx_resolve_name_done(rctx);
            return;
        }

        if (rc != NGX_OK) {
            ctx->outbound = saved_outbound;
            ctx->udp_route_restore_outbound = NULL;
            ngx_resolve_name_done(rctx);
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
        ctx->outbound = saved_outbound;
        ctx->udp_route_restore_outbound = NULL;

        ngx_resolve_name_done(rctx);
        if (ctx->inbound_socks5) {
            ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
            return;
        }

        ctx->state = ngx_stream_trojan_state_udp;
        ngx_stream_trojan_process_udp_client(ctx);
        return;
    }

    if (data->type == ngx_stream_trojan_resolve_tcp) {
        if (rctx->naddrs == 0
            || ngx_stream_trojan_resolver_addr_to_ngx_addr(
                   ctx->session->connection->pool,
                   ngx_stream_trojan_resolver_pick_addr(
                       rctx->addrs, rctx->naddrs, data->ip_prefer),
                   data->port, &addr)
               != NGX_OK)
        {
            ngx_resolve_name_done(rctx);
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ngx_resolve_name_done(rctx);
        ngx_stream_trojan_connect(ctx, &addr);
        return;
    }

    if (ngx_stream_trojan_send_udp_resolved(ctx, rctx->addrs, rctx->naddrs,
                                            data->port, data->payload,
                                            data->payload_len,
                                            data->ip_prefer)
        != NGX_OK)
    {
        ngx_resolve_name_done(rctx);
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    ngx_resolve_name_done(rctx);
    if (ctx->inbound_socks5) {
        ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
        return;
    }

    ctx->state = ngx_stream_trojan_state_udp;
    ngx_stream_trojan_process_udp_client(ctx);
}


static void
ngx_stream_trojan_connect(ngx_stream_trojan_ctx_t *ctx, ngx_addr_t *addr)
{
    ngx_int_t          rc;
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    ctx->state = ngx_stream_trojan_state_connecting;

    ngx_memzero(&ctx->peer, sizeof(ngx_peer_connection_t));
    ctx->peer.sockaddr = addr->sockaddr;
    ctx->peer.socklen = addr->socklen;
    ctx->peer_name = addr->name;
    ctx->peer.name = &ctx->peer_name;
    ctx->peer.type = SOCK_STREAM;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = c->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.tries = 1;
    ctx->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    pc = ctx->peer.connection;
    ctx->upstream = pc;

    pc->data = ctx;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;

    if (rc == NGX_AGAIN) {
        pc->read->handler = ngx_stream_trojan_peer_handler;
        pc->write->handler = ngx_stream_trojan_peer_handler;
        ngx_add_timer(pc->write, ctx->conf->connect_timeout);
        return;
    }

    ngx_stream_trojan_init_proxy(ctx);
}


static void
ngx_stream_trojan_start_socks5_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ngx_stream_trojan_ensure_pending(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->peer_kind = ngx_stream_trojan_peer_tcp;
    ngx_stream_trojan_socks5_connect(ctx, ngx_stream_trojan_socks5_mode_tcp);
}


static void
ngx_stream_trojan_start_socks5_udp(ngx_stream_trojan_ctx_t *ctx)
{
    ctx->session->connection->write->handler =
        ngx_stream_trojan_udp_client_write_handler;

    ngx_stream_trojan_socks5_connect(ctx, ngx_stream_trojan_socks5_mode_udp);
}


static void
ngx_stream_trojan_close_socks5_udp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->socks5_udp != NULL) {
        ngx_close_connection(ctx->socks5_udp);
        ctx->socks5_udp = NULL;
    }

    if (ctx->upstream != NULL && ctx->socks5_udp_outbound != NULL) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    ctx->socks5_udp_relay.sockaddr = NULL;
    ctx->socks5_udp_relay.socklen = 0;
    ctx->socks5_udp_relay.name.len = 0;
    ctx->socks5_udp_outbound = NULL;
    ctx->socks5_connected = 0;
}


static void
ngx_stream_trojan_socks5_connect(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_socks5_mode_e mode)
{
    ngx_int_t          rc;
    ngx_connection_t  *c, *pc;

    if (ctx->outbound == NULL || ctx->outbound->socks5_server == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    c = ctx->session->connection;

    ctx->socks5_buffer = ngx_stream_trojan_create_temp_buf(
        c->pool, NGX_STREAM_TROJAN_SOCKS5_BUFFER_SIZE);
    if (ctx->socks5_buffer == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ctx->socks5_mode = mode;
    ctx->socks5_step = ngx_stream_trojan_socks5_step_greeting_write;
    ctx->state = mode == ngx_stream_trojan_socks5_mode_tcp
                 ? ngx_stream_trojan_state_socks5_tcp
                 : ngx_stream_trojan_state_socks5_udp;

    if (ngx_stream_trojan_socks5_prepare_greeting(ctx) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    ngx_memzero(&ctx->peer, sizeof(ngx_peer_connection_t));
    ctx->peer.sockaddr = ctx->outbound->socks5_server->sockaddr;
    ctx->peer.socklen = ctx->outbound->socks5_server->socklen;
    ctx->peer_name = ctx->outbound->socks5_server->name;
    ctx->peer.name = &ctx->peer_name;
    ctx->peer.type = SOCK_STREAM;
    ctx->peer.get = ngx_event_get_peer;
    ctx->peer.log = c->log;
    ctx->peer.log_error = NGX_ERROR_ERR;
    ctx->peer.tries = 1;
    ctx->peer.start_time = ngx_current_msec;

    rc = ngx_event_connect_peer(&ctx->peer);

    if (rc == NGX_ERROR || rc == NGX_BUSY || rc == NGX_DECLINED) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    pc = ctx->peer.connection;
    ctx->upstream = pc;

    pc->data = ctx;
    pc->log = c->log;
    pc->pool = c->pool;
    pc->read->log = c->log;
    pc->write->log = c->log;
    pc->read->handler = ngx_stream_trojan_socks5_handler;
    pc->write->handler = ngx_stream_trojan_socks5_handler;

    ngx_add_timer(pc->write, ctx->conf->connect_timeout);

    if (rc == NGX_AGAIN) {
        return;
    }

    ctx->socks5_connected = 1;
    ngx_stream_trojan_process_socks5(ctx);
}


static void
ngx_stream_trojan_socks5_handler(ngx_event_t *ev)
{
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan socks5 timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (!ctx->socks5_connected) {
        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ctx->socks5_connected = 1;
    }

    ngx_stream_trojan_process_socks5(ctx);
}


static void
ngx_stream_trojan_process_socks5(ngx_stream_trojan_ctx_t *ctx)
{
    int                         rc;
    size_t                      needed, len;
    ngx_connection_t           *pc;
    ngx_stream_trojan_addr_t    bind_addr;

    pc = ctx->upstream;

    if (pc == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    for ( ;; ) {
        switch (ctx->socks5_step) {

        case ngx_stream_trojan_socks5_step_greeting_write:
            rc = ngx_stream_trojan_socks5_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_method_read;
            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            continue;

        case ngx_stream_trojan_socks5_step_method_read:
            rc = ngx_stream_trojan_socks5_read(ctx, 2);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            rc = ngx_stream_trojan_socks5_parse_method_response(
                ctx->socks5_buffer->pos, 2,
                ctx->outbound->socks5_username.len != 0);

            if (rc == 1) {
                if (ngx_stream_trojan_socks5_prepare_auth(ctx) != NGX_OK) {
                    ngx_stream_trojan_finalize(
                        ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                ctx->socks5_step = ngx_stream_trojan_socks5_step_auth_write;
                continue;
            }

            if (rc != 0) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ngx_stream_trojan_socks5_prepare_request(ctx) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_request_write;
            continue;

        case ngx_stream_trojan_socks5_step_auth_write:
            rc = ngx_stream_trojan_socks5_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_auth_read;
            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            continue;

        case ngx_stream_trojan_socks5_step_auth_read:
            rc = ngx_stream_trojan_socks5_read(ctx, 2);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK
                || ngx_stream_trojan_socks5_parse_auth_response(
                       ctx->socks5_buffer->pos, 2)
                   != 0)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (ngx_stream_trojan_socks5_prepare_request(ctx) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_request_write;
            continue;

        case ngx_stream_trojan_socks5_step_request_write:
            rc = ngx_stream_trojan_socks5_flush(ctx);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_step = ngx_stream_trojan_socks5_step_response_read;
            ctx->socks5_buffer->pos = ctx->socks5_buffer->start;
            ctx->socks5_buffer->last = ctx->socks5_buffer->start;
            continue;

        case ngx_stream_trojan_socks5_step_response_read:
            len = ctx->socks5_buffer->last - ctx->socks5_buffer->pos;
            rc = ngx_stream_trojan_socks5_response_len(
                ctx->socks5_buffer->pos, len, &needed);

            if (rc == 1) {
                rc = ngx_stream_trojan_socks5_read(ctx, needed);
                if (rc == NGX_AGAIN) {
                    return;
                }

                if (rc != NGX_OK) {
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                    return;
                }

                continue;
            }

            if (rc != 0
                || ngx_stream_trojan_socks5_parse_response(
                       ctx->socks5_buffer->pos, len, &bind_addr)
                   != 0)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (pc->write->timer_set) {
                ngx_del_timer(pc->write);
            }

            if (ctx->socks5_mode == ngx_stream_trojan_socks5_mode_tcp) {
                ngx_stream_trojan_init_proxy(ctx);
                return;
            }

            if (ngx_stream_trojan_socks5_response_to_ngx_addr(
                    ctx, &bind_addr, &ctx->socks5_udp_relay)
                != NGX_OK)
            {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            ctx->socks5_udp = ngx_stream_trojan_create_udp_connection(
                ctx, ctx->socks5_udp_relay.sockaddr->sa_family,
                ngx_stream_trojan_socks5_udp_read_handler);
            if (ctx->socks5_udp == NULL) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }
            ctx->socks5_udp_outbound = ctx->outbound;

            pc->read->handler = ngx_stream_trojan_socks5_udp_control_handler;
            pc->write->handler = ngx_stream_trojan_socks5_udp_control_handler;
            ngx_add_timer(pc->read, ctx->conf->udp_timeout);
            if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx,
                                           NGX_STREAM_INTERNAL_SERVER_ERROR);
                return;
            }

            if (ctx->udp_route_pending) {
                ngx_stream_trojan_udp_frame_t frame;
                ngx_stream_trojan_outbound_t *saved;

                frame.addr = ctx->udp_route_addr;
                frame.payload = ctx->udp_payload;
                frame.payload_len = ctx->udp_route_payload_len;
                frame.wire_len = 0;

                saved = ctx->outbound;
                ctx->outbound = ctx->udp_route_saved_outbound;
                ctx->udp_route_pending = 0;

                if (ngx_stream_trojan_send_socks5_udp_frame(ctx, &frame)
                    != NGX_OK)
                {
                    ctx->outbound = ctx->udp_route_restore_outbound != NULL
                                    ? ctx->udp_route_restore_outbound
                                    : saved;
                    ctx->udp_route_restore_outbound = NULL;
                    ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                    return;
                }

                ctx->outbound = ctx->udp_route_restore_outbound != NULL
                                ? ctx->udp_route_restore_outbound
                                : saved;
                ctx->udp_route_restore_outbound = NULL;
            }

            if (ctx->inbound_socks5) {
                ctx->state = ngx_stream_trojan_state_socks5_in_udp_control;
                ctx->session->connection->read->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ctx->session->connection->write->handler =
                    ngx_stream_trojan_socks5_in_udp_control_handler;
                ngx_add_timer(ctx->session->connection->read,
                              ctx->conf->udp_timeout);
                if (ngx_handle_read_event(ctx->session->connection->read, 0)
                    != NGX_OK)
                {
                    ngx_stream_trojan_finalize(ctx,
                                               NGX_STREAM_INTERNAL_SERVER_ERROR);
                    return;
                }

                return;
            }

            ctx->state = ngx_stream_trojan_state_udp;
            ngx_add_timer(ctx->session->connection->read,
                          ctx->conf->udp_timeout);
            ngx_stream_trojan_process_udp_client(ctx);
            return;
        }
    }
}


static ngx_int_t
ngx_stream_trojan_socks5_flush(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *pc;
    ngx_buf_t         *b;

    pc = ctx->upstream;
    b = ctx->socks5_buffer;

    while (b->pos < b->last) {
        n = pc->send(pc, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(pc->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_read(ngx_stream_trojan_ctx_t *ctx, size_t needed)
{
    size_t             available;
    ssize_t            n;
    ngx_connection_t  *pc;
    ngx_buf_t         *b;

    pc = ctx->upstream;
    b = ctx->socks5_buffer;

    if (needed > (size_t) (b->end - b->start)) {
        return NGX_ERROR;
    }

    while ((size_t) (b->last - b->pos) < needed) {
        available = needed - (size_t) (b->last - b->pos);
        n = pc->recv(pc, b->last, available);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == 0 || n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->last += n;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_prepare_greeting(ngx_stream_trojan_ctx_t *ctx)
{
    size_t      written;
    ngx_buf_t  *b;

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_socks5_build_greeting(
            b->last, b->end - b->last, ctx->outbound->socks5_username.len != 0,
            &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_prepare_auth(ngx_stream_trojan_ctx_t *ctx)
{
    size_t      written;
    ngx_buf_t  *b;

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ngx_stream_trojan_socks5_build_auth(
            ctx->outbound->socks5_username.data,
            ctx->outbound->socks5_username.len,
            ctx->outbound->socks5_password.data,
            ctx->outbound->socks5_password.len,
            b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_prepare_request(ngx_stream_trojan_ctx_t *ctx)
{
    size_t                      written;
    ngx_buf_t                  *b;
    ngx_stream_trojan_addr_t    bind_addr;
    u_char                      zero[4] = { 0, 0, 0, 0 };

    b = ctx->socks5_buffer;
    b->pos = b->start;
    b->last = b->start;

    if (ctx->socks5_mode == ngx_stream_trojan_socks5_mode_tcp) {
        if (ngx_stream_trojan_socks5_build_request(
                NGX_STREAM_TROJAN_SOCKS5_CMD_CONNECT, &ctx->target,
                b->last, b->end - b->last, &written)
            != 0)
        {
            return NGX_ERROR;
        }

        b->last += written;
        return NGX_OK;
    }

    ngx_memzero(&bind_addr, sizeof(bind_addr));
    bind_addr.type = NGX_STREAM_TROJAN_ADDR_IPV4;
    bind_addr.host_len = 4;
    ngx_memcpy(bind_addr.host, zero, 4);
    bind_addr.port = 0;
    bind_addr.wire_len = 1 + 4 + 2;

    if (ngx_stream_trojan_socks5_build_request(
            NGX_STREAM_TROJAN_SOCKS5_CMD_UDP_ASSOCIATE, &bind_addr,
            b->last, b->end - b->last, &written)
        != 0)
    {
        return NGX_ERROR;
    }

    b->last += written;
    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_socks5_response_to_ngx_addr(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    ngx_int_t              rc;
    struct sockaddr        *sa;
    struct sockaddr_in     *sin, *server_sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6    *sin6, *server_sin6;
#endif

    rc = ngx_stream_trojan_addr_to_ngx_addr(ctx->session->connection->pool,
                                            addr, out);
    if (rc == NGX_DECLINED) {
        rc = ngx_stream_trojan_resolve_addr(ctx->session->connection->pool,
                                            ctx->session->connection->log,
                                            addr, out);
    }

    if (rc != NGX_OK) {
        return NGX_ERROR;
    }

    sa = out->sockaddr;

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        if (sin->sin_addr.s_addr == INADDR_ANY
            && ctx->outbound->socks5_server->sockaddr->sa_family == AF_INET)
        {
            server_sin = (struct sockaddr_in *)
                         ctx->outbound->socks5_server->sockaddr;
            sin->sin_addr = server_sin->sin_addr;
        }
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        if (IN6_IS_ADDR_UNSPECIFIED(&sin6->sin6_addr)
            && ctx->outbound->socks5_server->sockaddr->sa_family == AF_INET6)
        {
            server_sin6 = (struct sockaddr_in6 *)
                          ctx->outbound->socks5_server->sockaddr;
            sin6->sin6_addr = server_sin6->sin6_addr;
        }
    }
#endif

    out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                  out->name.data, NGX_SOCKADDR_STRLEN, 1);

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_select_outbound(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_route_resume_e resume)
{
    ngx_uint_t                         needs_resolve, ttl_cache;
    ngx_stream_trojan_outbound_t      *outbound;
    ngx_stream_trojan_route_cache_entry_t *cached;
    ngx_stream_trojan_route_addrs_t     resolved;

    if (ctx->conf->outbounds == NULL
        || ctx->conf->outbounds->nelts == 0)
    {
        ctx->outbound = NULL;
        ctx->route_entry = NULL;
        return NGX_OK;
    }

    ngx_stream_trojan_route_resolve_target(ctx, target);

    if (!ctx->conf->route_enabled) {
        outbound = ctx->conf->outbounds->elts;
        ctx->outbound = &outbound[0];
        ctx->route_entry = NULL;
        return NGX_OK;
    }

    cached = ngx_stream_trojan_route_cache_lookup(ctx->conf->route_cache,
                                                  target);
    if (cached != NULL) {
        if (cached->ttl && cached->expires <= ngx_time()) {
            if (ngx_stream_trojan_route_resolver_kind(ctx)
                != ngx_stream_trojan_route_resolver_nginx)
            {
                goto route_cache_miss;
            }

            ctx->outbound = cached->outbound;
            ctx->route_entry = cached;
            if (!cached->refreshing) {
                ngx_stream_trojan_route_cache_start_refresh(ctx, target, cached);
            }

            return NGX_OK;
        }

        ctx->outbound = cached->outbound;
        ctx->route_entry = cached;
        return NGX_OK;
    }

route_cache_miss:

    needs_resolve = 0;
    ttl_cache = 0;
    outbound = ngx_stream_trojan_select_outbound_now(ctx, target, NULL, 0, 0,
                                                     &needs_resolve,
                                                     &ttl_cache);
    if (outbound != NULL) {
        ctx->outbound = outbound;
        ctx->route_entry = ngx_stream_trojan_route_cache_insert(
            ctx->conf->route_cache, target, outbound, ttl_cache, 0);
        return NGX_OK;
    }

    if (needs_resolve) {
        if (ngx_stream_trojan_route_resolver_kind(ctx)
            != ngx_stream_trojan_route_resolver_nginx)
        {
            if (ngx_stream_trojan_route_system_resolve(ctx, target, &resolved)
                != NGX_OK)
            {
                ctx->outbound = NULL;
                return NGX_OK;
            }

            outbound = ngx_stream_trojan_select_outbound_now(
                ctx, target, resolved.addrs, resolved.naddrs, 1, NULL,
                &ttl_cache);
            if (outbound != NULL) {
                ctx->outbound = outbound;
                ctx->route_entry = ngx_stream_trojan_route_cache_insert(
                    ctx->conf->route_cache, target, outbound, ttl_cache,
                    ngx_time() + NGX_STREAM_TROJAN_DEFAULT_ROUTE_CACHE_TTL);
                return NGX_OK;
            }

            ctx->outbound = NULL;
            return NGX_OK;
        }

        return ngx_stream_trojan_start_route_resolver(ctx, target, resume);
    }

    ctx->outbound = NULL;
    ctx->route_entry = NULL;
    return NGX_OK;
}


static void
ngx_stream_trojan_route_resolve_target(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target)
{
    if (ctx->conf->route_resolve == ngx_stream_trojan_route_resolve_off) {
        return;
    }

    if (target == NULL || target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        return;
    }

    (void) ngx_stream_trojan_normalize_ip_literal(target);
}


static ngx_stream_trojan_outbound_t *
ngx_stream_trojan_select_outbound_now(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs, ngx_uint_t lazy_used, ngx_uint_t *needs_resolve,
    ngx_uint_t *ttl_cache)
{
    ngx_uint_t                   i;
    ngx_stream_trojan_outbound_t *outbound;

    if (ctx->conf->outbounds == NULL) {
        return NULL;
    }

    outbound = ctx->conf->outbounds->elts;

    for (i = 0; i < ctx->conf->outbounds->nelts; i++) {
        if (ngx_stream_trojan_outbound_matches_domain(&outbound[i], target)) {
            if (ttl_cache != NULL) {
                *ttl_cache = lazy_used
                             && target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN
                             && (outbound[i].match_all
                                 || !outbound[i].has_rules)
                             ? 1 : 0;
            }
            return &outbound[i];
        }

        if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN
            && ctx->conf->route_resolve == ngx_stream_trojan_route_resolve_lazy
            && ngx_stream_trojan_outbound_has_ip_rules(&outbound[i]))
        {
            if (addrs == NULL || naddrs == 0) {
                if (needs_resolve != NULL) {
                    *needs_resolve = 1;
                }
                return NULL;
            }

            if (ngx_stream_trojan_outbound_matches_resolved_ip(&outbound[i],
                                                               addrs, naddrs))
            {
                if (ttl_cache != NULL) {
                    *ttl_cache = 1;
                }
                return &outbound[i];
            }
        }

        if (target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
            && ngx_stream_trojan_outbound_matches(ctx, &outbound[i], target))
        {
            if (ttl_cache != NULL) {
                *ttl_cache = 0;
            }
            return &outbound[i];
        }
    }

    return NULL;
}


static ngx_uint_t
ngx_stream_trojan_outbound_matches(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_outbound_t *outbound, ngx_stream_trojan_addr_t *target)
{
    ngx_stream_trojan_rule_match_e    match;

    if (outbound->match_all || !outbound->has_rules) {
        return 1;
    }

    if (outbound->matcher == NULL) {
        return 0;
    }

    match = ngx_stream_trojan_route_rules_match_target(outbound->matcher,
                                                       target);

    (void) ctx;
    return match == NGX_STREAM_TROJAN_RULE_MATCH;
}


static ngx_uint_t
ngx_stream_trojan_outbound_matches_domain(
    ngx_stream_trojan_outbound_t *outbound, ngx_stream_trojan_addr_t *target)
{
    ngx_str_t                       host;
    ngx_stream_trojan_rule_match_e  match;

    if (outbound->match_all || !outbound->has_rules) {
        return 1;
    }

    if (outbound->matcher == NULL || target == NULL
        || target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN)
    {
        return 0;
    }

    host.data = target->host;
    host.len = target->host_len;

    match = ngx_stream_trojan_route_rules_match_domain(outbound->matcher,
                                                       &host);

    return match == NGX_STREAM_TROJAN_RULE_MATCH;
}


static ngx_uint_t
ngx_stream_trojan_outbound_has_ip_rules(ngx_stream_trojan_outbound_t *outbound)
{
    return outbound != NULL && outbound->matcher != NULL
           && outbound->matcher->ips.nelts != 0;
}


static ngx_uint_t
ngx_stream_trojan_outbound_matches_resolved_ip(
    ngx_stream_trojan_outbound_t *outbound, ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs)
{
    ngx_uint_t                       i;
    ngx_stream_trojan_rule_match_e   match;

    if (outbound == NULL || outbound->matcher == NULL || addrs == NULL) {
        return 0;
    }

    for (i = 0; i < naddrs; i++) {
        if (addrs[i].sockaddr == NULL) {
            continue;
        }

        match = ngx_stream_trojan_route_rules_match_ip(outbound->matcher,
                                                       addrs[i].sockaddr);
        if (match == NGX_STREAM_TROJAN_RULE_MATCH) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_stream_trojan_start_route_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_route_resume_e resume)
{
    ngx_int_t  rc;

    if (ngx_stream_trojan_route_resolver_kind(ctx)
        != ngx_stream_trojan_route_resolver_nginx)
    {
        return NGX_ERROR;
    }

    ctx->route_resume = resume;

    rc = ngx_stream_trojan_start_resolver(ctx, target,
                                          ngx_stream_trojan_resolve_route,
                                          NULL, 0, 0);

    return rc == NGX_OK ? NGX_AGAIN : rc;
}


static ngx_int_t
ngx_stream_trojan_start_udp_route_resolver(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    ngx_int_t  rc;

    if (ngx_stream_trojan_route_resolver_kind(ctx)
        != ngx_stream_trojan_route_resolver_nginx)
    {
        return NGX_ERROR;
    }

    rc = ngx_stream_trojan_start_resolver(ctx, &frame->addr,
                                          ngx_stream_trojan_resolve_udp_route,
                                          frame->payload,
                                          frame->payload_len,
                                          frame->wire_len);

    return rc == NGX_OK ? NGX_AGAIN : rc;
}


static ngx_int_t
ngx_stream_trojan_route_system_resolve(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_route_addrs_t *resolved)
{
    char             host[256], service[6];
    int              rc;
    struct addrinfo  hints, *res, *rp;

    if (target == NULL || target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || target->host_len == 0 || target->host_len >= sizeof(host)
        || resolved == NULL)
    {
        return NGX_ERROR;
    }

    ngx_memcpy(host, target->host, target->host_len);
    host[target->host_len] = '\0';
    ngx_snprintf((u_char *) service, sizeof(service), "%ui%Z",
                 (ngx_uint_t) target->port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    res = NULL;
    rc = getaddrinfo(host, service, &hints, &res);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log, 0,
                      "getaddrinfo(\"%s\") for route failed: %s", host,
                      gai_strerror(rc));
        return NGX_ERROR;
    }

    ngx_memzero(resolved, sizeof(*resolved));

    for (rp = res; rp != NULL
         && resolved->naddrs < NGX_STREAM_TROJAN_ROUTE_MAX_SYSTEM_ADDRS;
         rp = rp->ai_next)
    {
        if (rp->ai_addr == NULL
            || rp->ai_addrlen > sizeof(resolved->sockaddr[0]))
        {
            continue;
        }

        if (rp->ai_addr->sa_family != AF_INET
#if (NGX_HAVE_INET6)
            && rp->ai_addr->sa_family != AF_INET6
#endif
            )
        {
            continue;
        }

        ngx_memcpy(&resolved->sockaddr[resolved->naddrs], rp->ai_addr,
                   rp->ai_addrlen);
        resolved->addrs[resolved->naddrs].sockaddr =
            (struct sockaddr *) &resolved->sockaddr[resolved->naddrs];
        resolved->addrs[resolved->naddrs].socklen = rp->ai_addrlen;
        resolved->naddrs++;
    }

    freeaddrinfo(res);

    return resolved->naddrs != 0 ? NGX_OK : NGX_ERROR;
}


static ngx_uint_t
ngx_stream_trojan_route_resolver_kind(ngx_stream_trojan_ctx_t *ctx)
{
    return ngx_stream_trojan_route_resolver(ctx) != NULL
           ? ngx_stream_trojan_route_resolver_nginx
           : ngx_stream_trojan_route_resolver_system;
}


static ngx_resolver_t *
ngx_stream_trojan_route_resolver(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_stream_core_srv_conf_t *cscf;

    cscf = ngx_stream_trojan_core_srv_conf(ctx);
    if (cscf != NULL
        && NGX_STREAM_TROJAN_RESOLVER_HAS_CONNECTIONS(cscf->resolver))
    {
        return cscf->resolver;
    }

    if (ctx != NULL && ctx->conf != NULL
        && NGX_STREAM_TROJAN_RESOLVER_HAS_CONNECTIONS(
               ctx->conf->route_resolver))
    {
        return ctx->conf->route_resolver;
    }

    return NULL;
}


static ngx_uint_t
ngx_stream_trojan_needs_internal_resolver(ngx_stream_trojan_srv_conf_t *tscf)
{
    ngx_uint_t                    i;
    ngx_stream_trojan_outbound_t *outbound;

    if (tscf == NULL) {
        return 0;
    }

    if (tscf->route_enabled
        && tscf->route_resolve == ngx_stream_trojan_route_resolve_lazy)
    {
        return 1;
    }

    if (tscf->outbounds == NULL || tscf->outbounds->nelts == 0) {
        return 1;
    }

    outbound = tscf->outbounds->elts;
    for (i = 0; i < tscf->outbounds->nelts; i++) {
        if (outbound[i].type == ngx_stream_trojan_outbound_direct) {
            return 1;
        }
    }

    return 0;
}


static ngx_int_t
ngx_stream_trojan_create_internal_route_resolver(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *tscf)
{
    ngx_array_t                  names;
    ngx_stream_core_srv_conf_t  *cscf;

    if (!ngx_stream_trojan_needs_internal_resolver(tscf)) {
        return NGX_OK;
    }

    cscf = tscf->core_srv_conf;
    if (cscf != NULL
        && NGX_STREAM_TROJAN_RESOLVER_HAS_CONNECTIONS(cscf->resolver))
    {
        return NGX_OK;
    }

    if (tscf->route_resolver != NULL) {
        return NGX_OK;
    }

    if (ngx_array_init(&names, cf->pool, 2, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_ERROR;
    }

    if (ngx_stream_trojan_read_system_nameservers(cf, &names) != NGX_OK
        || names.nelts == 0)
    {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                           "could not read usable "
                           "nameserver from " NGX_STREAM_TROJAN_RESOLV_CONF
                           ", fallback to system DNS");
        return NGX_OK;
    }

    tscf->route_resolver = ngx_resolver_create(cf, names.elts, names.nelts);
    if (tscf->route_resolver == NULL) {
        return NGX_ERROR;
    }

    tscf->route_internal_resolver = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_read_system_nameservers(ngx_conf_t *cf, ngx_array_t *names)
{
    FILE       *fp;
    char        line[512], *p, *start, *end;
    size_t      i, len;
    ngx_uint_t  ipv6;
    ngx_str_t  *name;

    fp = fopen(NGX_STREAM_TROJAN_RESOLV_CONF, "r");
    if (fp == NULL) {
        return NGX_DECLINED;
    }

    while (fgets(line, sizeof(line), fp) != NULL) {
        p = line;

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        if (*p == '#' || *p == ';' || *p == '\0') {
            continue;
        }

        if (ngx_strncmp((u_char *) p, "nameserver", 10) != 0) {
            continue;
        }

        p += 10;
        if (*p != ' ' && *p != '\t') {
            continue;
        }

        while (*p == ' ' || *p == '\t') {
            p++;
        }

        start = p;
        while (*p != '\0' && *p != '\n' && *p != '\r'
               && *p != ' ' && *p != '\t' && *p != '#'
               && *p != ';')
        {
            p++;
        }
        end = p;

        if (end == start) {
            continue;
        }

        len = (size_t) (end - start);
        ipv6 = 0;
        for (i = 0; i < len; i++) {
            if (start[i] == ':') {
                ipv6 = 1;
                break;
            }
        }

        name = ngx_array_push(names);
        if (name == NULL) {
            fclose(fp);
            return NGX_ERROR;
        }

        if (ipv6 && start[0] != '[') {
            name->data = ngx_pnalloc(cf->pool, len + 2);
            if (name->data == NULL) {
                fclose(fp);
                return NGX_ERROR;
            }

            name->data[0] = '[';
            ngx_memcpy(name->data + 1, start, len);
            name->data[len + 1] = ']';
            name->len = len + 2;
            continue;
        }

        name->data = ngx_pnalloc(cf->pool, len);
        if (name->data == NULL) {
            fclose(fp);
            return NGX_ERROR;
        }

        ngx_memcpy(name->data, start, len);
        name->len = len;
    }

    fclose(fp);

    return NGX_OK;
}


static time_t
ngx_stream_trojan_route_valid_time(ngx_resolver_ctx_t *rctx)
{
    if (rctx->valid > ngx_time()) {
        return rctx->valid;
    }

    return ngx_time() + NGX_STREAM_TROJAN_DEFAULT_ROUTE_CACHE_TTL;
}


static void
ngx_stream_trojan_route_cache_start_refresh(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_route_cache_entry_t *entry)
{
    ngx_str_t                         name;
    ngx_resolver_ctx_t               *rctx, temp;
    ngx_resolver_t                   *resolver;
    ngx_stream_core_srv_conf_t       *cscf;
    ngx_stream_trojan_route_refresh_t *refresh;

    if (entry == NULL || entry->refreshing
        || target == NULL || target->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || target->host_len == 0 || target->host_len > 255)
    {
        return;
    }

    if (ngx_stream_trojan_route_resolver_kind(ctx)
        != ngx_stream_trojan_route_resolver_nginx)
    {
        return;
    }

    refresh = ngx_alloc(sizeof(ngx_stream_trojan_route_refresh_t),
                        ctx->session->connection->log);
    if (refresh == NULL) {
        return;
    }

    ngx_memzero(refresh, sizeof(*refresh));

    name.data = ngx_alloc(target->host_len, ctx->session->connection->log);
    if (name.data == NULL) {
        ngx_free(refresh);
        return;
    }

    ngx_memcpy(name.data, target->host, target->host_len);
    name.len = target->host_len;

    refresh->conf = ctx->conf;
    refresh->cache = ctx->conf->route_cache;
    refresh->entry = entry;
    refresh->generation = entry->generation;
    refresh->name = name;
    refresh->target = *target;
    refresh->log = ngx_cycle->log;

    ngx_memzero(&temp, sizeof(ngx_resolver_ctx_t));
    temp.name = name;

    resolver = ngx_stream_trojan_route_resolver(ctx);
    if (resolver == NULL) {
        ngx_stream_trojan_route_refresh_free(refresh);
        return;
    }

    cscf = ngx_stream_trojan_core_srv_conf(ctx);
    if (cscf == NULL) {
        ngx_stream_trojan_route_refresh_free(refresh);
        return;
    }

    rctx = ngx_resolve_start(resolver, &temp);
    if (rctx == NULL || rctx == NGX_NO_RESOLVER) {
        ngx_stream_trojan_route_refresh_free(refresh);
        return;
    }

    rctx->name = name;
    rctx->handler = ngx_stream_trojan_route_refresh_handler;
    rctx->data = refresh;
    rctx->timeout = cscf->resolver_timeout;

    entry->refreshing = 1;

    if (ngx_resolve_name(rctx) != NGX_OK) {
        entry->refreshing = 0;
        ngx_stream_trojan_route_refresh_free(refresh);
    }
}


static void
ngx_stream_trojan_route_refresh_handler(ngx_resolver_ctx_t *rctx)
{
    ngx_uint_t                         ttl_cache;
    ngx_stream_trojan_outbound_t      *outbound;
    ngx_stream_trojan_ctx_t            fake_ctx;
    ngx_stream_trojan_route_refresh_t *refresh;

    refresh = rctx->data;

    if (refresh == NULL) {
        ngx_resolve_name_done(rctx);
        return;
    }

    if (refresh->entry != NULL
        && refresh->entry->valid
        && refresh->entry->generation == refresh->generation)
    {
        refresh->entry->refreshing = 0;
    }

    if (rctx->state == 0 && rctx->naddrs != 0
        && refresh->entry != NULL
        && refresh->entry->valid
        && refresh->entry->generation == refresh->generation)
    {
        ttl_cache = 0;
        ngx_memzero(&fake_ctx, sizeof(fake_ctx));
        fake_ctx.conf = refresh->conf;

        outbound = ngx_stream_trojan_select_outbound_now(
            &fake_ctx, &refresh->target, rctx->addrs, rctx->naddrs, 1,
            NULL, &ttl_cache);

        if (outbound != NULL) {
            ngx_stream_trojan_route_cache_update_entry(
                refresh->cache, refresh->entry, outbound, ttl_cache,
                ngx_stream_trojan_route_valid_time(rctx));
        }
    }

    if (rctx->state != 0 && refresh->log != NULL) {
        ngx_log_error(NGX_LOG_ERR, refresh->log, 0,
                      "%V route refresh could not be resolved (%i: %s)",
                      &rctx->name, rctx->state,
                      ngx_resolver_strerror(rctx->state));
    }

    ngx_resolve_name_done(rctx);
    ngx_stream_trojan_route_refresh_free(refresh);
}


static void
ngx_stream_trojan_route_refresh_free(
    ngx_stream_trojan_route_refresh_t *refresh)
{
    if (refresh == NULL) {
        return;
    }

    if (refresh->name.data != NULL) {
        ngx_free(refresh->name.data);
    }

    ngx_free(refresh);
}


static ngx_uint_t
ngx_stream_trojan_outbound_type(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->outbound == NULL) {
        return ngx_stream_trojan_outbound_direct;
    }

    return ctx->outbound->type;
}


static ngx_uint_t
ngx_stream_trojan_current_block(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->outbound == NULL) {
        return ngx_stream_trojan_block_none;
    }

    return ctx->outbound->block;
}


static ngx_uint_t
ngx_stream_trojan_request_blocked(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_uint_t block;

    block = ngx_stream_trojan_current_block(ctx);

    if (block == ngx_stream_trojan_block_none) {
        return 0;
    }

    if (block == ngx_stream_trojan_block_all) {
        return 1;
    }

    if (ctx->command != NGX_STREAM_TROJAN_CMD_ASSOCIATE) {
        return 0;
    }

    if (block == ngx_stream_trojan_block_udp) {
        return 1;
    }

    if (block == ngx_stream_trojan_block_h3 && ctx->target.port == 443) {
        return 1;
    }

    return 0;
}


static ngx_uint_t
ngx_stream_trojan_udp_frame_blocked(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    ngx_stream_trojan_addr_t  original;
    ngx_uint_t                blocked;

    if (frame == NULL) {
        return 0;
    }

    original = ctx->target;
    ctx->target = frame->addr;
    blocked = ngx_stream_trojan_request_blocked(ctx);
    ctx->target = original;

    return blocked;
}


static ngx_int_t
ngx_stream_trojan_parse_ip_prefer(ngx_str_t *value, ngx_uint_t *prefer)
{
    if (value->len == 4 && ngx_strncmp(value->data, "auto", 4) == 0) {
        *prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
        return NGX_OK;
    }

    if (value->len == 4 && ngx_strncmp(value->data, "ipv4", 4) == 0) {
        *prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV4;
        return NGX_OK;
    }

    if (value->len == 4 && ngx_strncmp(value->data, "ipv6", 4) == 0) {
        *prefer = NGX_STREAM_TROJAN_IP_PREFER_IPV6;
        return NGX_OK;
    }

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_parse_block(ngx_str_t *value, ngx_uint_t *block)
{
    if (value->len == 4 && ngx_strncmp(value->data, "none", 4) == 0) {
        *block = ngx_stream_trojan_block_none;
        return NGX_OK;
    }

    if (value->len == 2 && ngx_strncmp(value->data, "h3", 2) == 0) {
        *block = ngx_stream_trojan_block_h3;
        return NGX_OK;
    }

    if (value->len == 3 && ngx_strncmp(value->data, "udp", 3) == 0) {
        *block = ngx_stream_trojan_block_udp;
        return NGX_OK;
    }

    if (value->len == 3 && ngx_strncmp(value->data, "all", 3) == 0) {
        *block = ngx_stream_trojan_block_all;
        return NGX_OK;
    }

    return NGX_ERROR;
}


static void
ngx_stream_trojan_outbound_init(ngx_stream_trojan_outbound_t *outbound,
    ngx_uint_t type)
{
    ngx_memzero(outbound, sizeof(*outbound));
    outbound->type = type;
    outbound->ip_prefer = NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    outbound->block = ngx_stream_trojan_block_none;
    outbound->match_all = 1;
}


static ngx_int_t
ngx_stream_trojan_outbound_set_tag(ngx_conf_t *cf,
    ngx_stream_trojan_outbound_t *outbound, ngx_str_t *tag)
{
    if (tag->len == 0
        || (tag->len == 1 && tag->data[0] == '*'))
    {
        outbound->match_all = 1;
        return NGX_OK;
    }

    if (ngx_stream_trojan_rule_reserved_value(tag)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid outbounds tag \"%V\"", tag);
        return NGX_ERROR;
    }

    outbound->tag = *tag;
    outbound->match_all = 0;
    outbound->has_rules = 1;

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_parse_server_ref(ngx_conf_t *cf, ngx_str_t *value,
    ngx_stream_trojan_server_ref_t *ref)
{
    u_char     *colon, *last, *p;
    ngx_int_t   port;
    ngx_str_t   port_part;
    ngx_addr_t  addr;

    if (value->len == 0) {
        goto invalid;
    }

    last = value->data + value->len;
    colon = ngx_strlchr(value->data, last, ':');
    if (colon == NULL || colon == value->data || colon + 1 == last) {
        goto invalid;
    }

    for (p = colon + 1; p < last; p++) {
        if (*p < '0' || *p > '9') {
            goto invalid;
        }
    }

    port_part.data = colon + 1;
    port_part.len = last - (colon + 1);
    port = ngx_atoi(port_part.data, port_part.len);
    if (port <= 0 || port > 65535) {
        goto invalid;
    }

    ref->host.data = value->data;
    ref->host.len = colon - value->data;
    ngx_strlow(ref->host.data, ref->host.data, ref->host.len);
    ref->port = (in_port_t) port;
    ref->set = 1;

    if (ref->host.len == sizeof("localhost") - 1
        && ngx_strncmp(ref->host.data, "localhost", ref->host.len) == 0)
    {
        ref->localhost = 1;
        return NGX_OK;
    }

    if (ngx_parse_addr(cf->pool, &addr, ref->host.data, ref->host.len)
        == NGX_OK)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_server \"%V\" does not support IP address; "
                           "use localhost:port or server_name:port",
                           value);
        return NGX_ERROR;
    }

    return NGX_OK;

invalid:

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid trojan_server \"%V\", expected name:port",
                       value);
    return NGX_ERROR;
}


static ngx_uint_t
ngx_stream_trojan_current_ip_prefer(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx->outbound == NULL
        || ctx->outbound->type != ngx_stream_trojan_outbound_direct)
    {
        return NGX_STREAM_TROJAN_IP_PREFER_AUTO;
    }

    return ctx->outbound->ip_prefer;
}


static void
ngx_stream_trojan_peer_handler(ngx_event_t *ev)
{
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_connecting) {
        if (ev->timedout) {
            ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan upstream timed out");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    } else if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT, "trojan upstream idle timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (ctx->state == ngx_stream_trojan_state_connecting) {
        if (pc->write->timer_set) {
            ngx_del_timer(pc->write);
        }

        if (ngx_stream_trojan_test_connect(pc) != NGX_OK) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        ngx_stream_trojan_init_proxy(ctx);
        return;
    }

    ngx_stream_trojan_process_proxy(ctx);
}


static ngx_int_t
ngx_stream_trojan_test_connect(ngx_connection_t *c)
{
    int        err;
    socklen_t  len;

#if (NGX_HAVE_KQUEUE)
    if (ngx_event_flags & NGX_USE_KQUEUE_EVENT) {
        err = c->write->kq_errno ? c->write->kq_errno : c->read->kq_errno;

        if (err) {
            (void) ngx_connection_error(c, err,
                                        "kevent() reported that connect() failed");
            return NGX_ERROR;
        }

    } else
#endif
    {
        err = 0;
        len = sizeof(int);

        if (getsockopt(c->fd, SOL_SOCKET, SO_ERROR, (void *) &err, &len) == -1) {
            err = ngx_socket_errno;
        }

        if (err) {
            (void) ngx_connection_error(c, err, "connect() failed");
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


static void
ngx_stream_trojan_init_proxy(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    ctx->client_buffer = ngx_stream_trojan_create_temp_buf(c->pool,
                                                           ctx->conf->buffer_size);
    ctx->upstream_buffer = ngx_stream_trojan_create_temp_buf(c->pool,
                                                             ctx->conf->buffer_size);

    if (ctx->client_buffer == NULL || ctx->upstream_buffer == NULL) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    c->read->handler = ngx_stream_trojan_read_client;
    c->write->handler = ngx_stream_trojan_read_client;
    pc->read->handler = ngx_stream_trojan_peer_handler;
    pc->write->handler = ngx_stream_trojan_peer_handler;

    ngx_stream_trojan_route_track_tcp(ctx, ctx->route_entry);

    ctx->state = ngx_stream_trojan_state_proxy;
    ngx_stream_trojan_set_proxy_timeout(ctx);
    ngx_stream_trojan_process_proxy(ctx);
}


static void
ngx_stream_trojan_set_proxy_timeout(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;

    if (!c->read->timer_set) {
        ngx_add_timer(c->read, ctx->conf->timeout);
    }

    if (pc && !pc->read->timer_set) {
        ngx_add_timer(pc->read, ctx->conf->timeout);
    }
}


static void
ngx_stream_trojan_process_proxy(ngx_stream_trojan_ctx_t *ctx)
{
    ngx_uint_t         client_eof, upstream_eof;
    ngx_connection_t  *c, *pc;

    c = ctx->session->connection;
    pc = ctx->upstream;
    client_eof = c->read->eof || c->read->error;
    upstream_eof = pc->read->eof || pc->read->error;

    if (ctx->pending_to_upstream
        && ctx->pending_to_upstream->pos < ctx->pending_to_upstream->last)
    {
        if (ngx_stream_trojan_process_direction(ctx, NULL, pc,
                                                ctx->pending_to_upstream,
                                                &client_eof)
            != NGX_OK)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_stream_trojan_process_direction(ctx, c, pc, ctx->client_buffer,
                                            &client_eof)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (ngx_stream_trojan_process_direction(ctx, pc, c, ctx->upstream_buffer,
                                            &upstream_eof)
        != NGX_OK)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    if (client_eof && upstream_eof
        && ctx->client_buffer->pos == ctx->client_buffer->last
        && ctx->upstream_buffer->pos == ctx->upstream_buffer->last)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (ngx_stream_trojan_route_check_tcp_stale(ctx)) {
        return;
    }

    ngx_handle_read_event(c->read, 0);
    ngx_handle_write_event(c->write, 0);
    ngx_handle_read_event(pc->read, 0);
    ngx_handle_write_event(pc->write, 0);
}


static ngx_int_t
ngx_stream_trojan_process_direction(ngx_stream_trojan_ctx_t *ctx,
    ngx_connection_t *src, ngx_connection_t *dst, ngx_buf_t *buf,
    ngx_uint_t *src_eof)
{
    size_t        available, bytes, limit, loops;
    ssize_t       n;
    ngx_event_t  *rev;

    if (buf == NULL || dst == NULL) {
        return NGX_OK;
    }

    bytes = 0;
    limit = ngx_stream_trojan_relay_limit(ctx->conf->buffer_size);
    loops = 0;

    for ( ;; ) {
        while (buf->pos < buf->last) {
            n = dst->send(dst, buf->pos, buf->last - buf->pos);

            if (n == NGX_AGAIN) {
                return NGX_OK;
            }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        buf->pos += n;
        ngx_stream_trojan_route_touch_tcp(ctx);
    }

        buf->pos = buf->start;
        buf->last = buf->start;

        if (src == NULL || *src_eof) {
            return NGX_OK;
        }

        rev = src->read;

        if ((!rev->ready && !ngx_stream_trojan_client_buffered(ctx, src))
            || !ngx_stream_trojan_relay_should_continue(loops, bytes, limit))
        {
            return NGX_OK;
        }

        available = ngx_stream_trojan_relay_read_size(buf->end - buf->last,
                                                      bytes, limit);
        if (available == 0) {
            return NGX_OK;
        }

        n = ngx_stream_trojan_recv(ctx, src, buf->last, available);

        if (n == NGX_AGAIN) {
            return NGX_OK;
        }

        if (n == 0) {
            *src_eof = 1;
            rev->eof = 1;
            return NGX_OK;
        }

        if (n == NGX_ERROR) {
            *src_eof = 1;
            rev->error = 1;
            return NGX_OK;
        }

        buf->last += n;
        bytes += (size_t) n;
        loops++;
        ngx_stream_trojan_route_touch_tcp(ctx);
    }
}


static ngx_int_t
ngx_stream_trojan_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif
    u_char               *p;

    ngx_memzero(out, sizeof(ngx_addr_t));

    switch (addr->type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        sin = ngx_pcalloc(pool, sizeof(struct sockaddr_in));
        if (sin == NULL) {
            return NGX_ERROR;
        }

        sin->sin_family = AF_INET;
        sin->sin_port = htons(addr->port);
        ngx_memcpy(&sin->sin_addr, addr->host, 4);

        out->sockaddr = (struct sockaddr *) sin;
        out->socklen = sizeof(struct sockaddr_in);
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data, NGX_SOCKADDR_STRLEN, 1);
        return NGX_OK;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        sin6 = ngx_pcalloc(pool, sizeof(struct sockaddr_in6));
        if (sin6 == NULL) {
            return NGX_ERROR;
        }

        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(addr->port);
        ngx_memcpy(&sin6->sin6_addr, addr->host, 16);

        out->sockaddr = (struct sockaddr *) sin6;
        out->socklen = sizeof(struct sockaddr_in6);
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data, NGX_SOCKADDR_STRLEN, 1);
        return NGX_OK;
#endif

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        p = ngx_pnalloc(pool, addr->host_len + 1);
        if (p == NULL) {
            return NGX_ERROR;
        }
        ngx_memcpy(p, addr->host, addr->host_len);
        p[addr->host_len] = '\0';
        (void) p;
        return NGX_DECLINED;

    default:
        return NGX_ERROR;
    }
}


static ngx_int_t
ngx_stream_trojan_resolve_addr(ngx_pool_t *pool, ngx_log_t *log,
    ngx_stream_trojan_addr_t *addr, ngx_addr_t *out)
{
    return ngx_stream_trojan_resolve_addr_prefer(
        pool, log, addr, NGX_STREAM_TROJAN_IP_PREFER_AUTO, out);
}


static ngx_int_t
ngx_stream_trojan_resolve_addr_prefer(ngx_pool_t *pool, ngx_log_t *log,
    ngx_stream_trojan_addr_t *addr, ngx_uint_t ip_prefer, ngx_addr_t *out)
{
    char                  host[256];
    char                  service[6];
    int                   rc;
    struct addrinfo       hints;
    struct addrinfo      *res, *rp, *selected;
    struct sockaddr      *sa;
    socklen_t             socklen;

    if (addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        return ngx_stream_trojan_addr_to_ngx_addr(pool, addr, out);
    }

    if (addr->host_len == 0 || addr->host_len >= sizeof(host)) {
        return NGX_ERROR;
    }

    ngx_memcpy(host, addr->host, addr->host_len);
    host[addr->host_len] = '\0';
    ngx_snprintf((u_char *) service, sizeof(service), "%ui%Z",
                 (ngx_uint_t) addr->port);

    ngx_memzero(&hints, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    rc = getaddrinfo(host, service, &hints, &res);
    if (rc != 0) {
        ngx_log_error(NGX_LOG_ERR, log, 0,
                      "getaddrinfo(\"%s\") failed: %s", host,
                      gai_strerror(rc));
        return NGX_ERROR;
    }

    selected = NULL;

    for (rp = res; rp != NULL; rp = rp->ai_next) {
        if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
            if (selected == NULL) {
                selected = rp;
            }

            if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV4
                && rp->ai_family == AF_INET)
            {
                selected = rp;
                break;
            }

#if (NGX_HAVE_INET6)
            if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6
                && rp->ai_family == AF_INET6)
            {
                selected = rp;
                break;
            }
#endif
        }
    }

    if (selected != NULL) {
        socklen = selected->ai_addrlen;
        sa = ngx_pnalloc(pool, socklen);
        if (sa == NULL) {
            freeaddrinfo(res);
            return NGX_ERROR;
        }

        ngx_memcpy(sa, selected->ai_addr, socklen);
        out->sockaddr = sa;
        out->socklen = socklen;
        out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
        if (out->name.data == NULL) {
            freeaddrinfo(res);
            return NGX_ERROR;
        }
        out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                      out->name.data,
                                      NGX_SOCKADDR_STRLEN, 1);
        freeaddrinfo(res);
        return NGX_OK;
    }

    freeaddrinfo(res);
    return NGX_ERROR;
}


static ngx_stream_core_srv_conf_t *
ngx_stream_trojan_core_srv_conf(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx == NULL) {
        return NULL;
    }

    if (ctx->conf != NULL && ctx->conf->core_srv_conf != NULL) {
        return ctx->conf->core_srv_conf;
    }

    return ngx_stream_get_module_srv_conf(ctx->session, ngx_stream_core_module);
}


static ngx_resolver_addr_t *
ngx_stream_trojan_resolver_pick_addr(ngx_resolver_addr_t *addrs,
    ngx_uint_t naddrs, ngx_uint_t ip_prefer)
{
    ngx_uint_t i;

    if (addrs == NULL || naddrs == 0) {
        return NULL;
    }

    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV4) {
        for (i = 0; i < naddrs; i++) {
            if (addrs[i].sockaddr->sa_family == AF_INET) {
                return &addrs[i];
            }
        }
    }

#if (NGX_HAVE_INET6)
    if (ip_prefer == NGX_STREAM_TROJAN_IP_PREFER_IPV6) {
        for (i = 0; i < naddrs; i++) {
            if (addrs[i].sockaddr->sa_family == AF_INET6) {
                return &addrs[i];
            }
        }
    }
#endif

    return &addrs[0];
}


static ngx_int_t
ngx_stream_trojan_resolver_addr_to_ngx_addr(ngx_pool_t *pool,
    ngx_resolver_addr_t *resolved, uint16_t port, ngx_addr_t *out)
{
    struct sockaddr  *sa;

    if (resolved == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(out, sizeof(ngx_addr_t));

    sa = ngx_pnalloc(pool, resolved->socklen);
    if (sa == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sa, resolved->sockaddr, resolved->socklen);
    ngx_inet_set_port(sa, port);

    out->sockaddr = sa;
    out->socklen = resolved->socklen;
    out->name.data = ngx_pnalloc(pool, NGX_SOCKADDR_STRLEN);
    if (out->name.data == NULL) {
        return NGX_ERROR;
    }
    out->name.len = ngx_sock_ntop(out->sockaddr, out->socklen,
                                  out->name.data, NGX_SOCKADDR_STRLEN, 1);

    return NGX_OK;
}


static ngx_connection_t *
ngx_stream_trojan_create_udp_connection(ngx_stream_trojan_ctx_t *ctx,
    int family, ngx_event_handler_pt handler)
{
    ngx_socket_t       fd;
    ngx_connection_t  *uc;

    fd = ngx_socket(family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_socket_n " failed");
        return NULL;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_nonblocking_n " failed");
        ngx_close_socket(fd);
        return NULL;
    }

    uc = ngx_get_connection(fd, ctx->session->connection->log);
    if (uc == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    uc->data = ctx;
    uc->log = ctx->session->connection->log;
    uc->read->handler = handler;
    uc->write->handler = handler;

    if (ngx_add_event(uc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_close_connection(uc);
        return NULL;
    }

    return uc;
}


static ngx_connection_t *
ngx_stream_trojan_create_bound_udp_connection(ngx_stream_trojan_ctx_t *ctx,
    int family, ngx_event_handler_pt handler)
{
    ngx_socket_t          fd;
    ngx_connection_t     *uc;
    struct sockaddr_in    sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   sin6;
#endif
    struct sockaddr      *sa;
    socklen_t             socklen;

    fd = ngx_socket(family, SOCK_DGRAM, 0);
    if (fd == (ngx_socket_t) -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_socket_n " failed");
        return NULL;
    }

    if (family == AF_INET) {
        ngx_memzero(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        sin.sin_port = 0;
        sa = (struct sockaddr *) &sin;
        socklen = sizeof(sin);

#if (NGX_HAVE_INET6)
    } else if (family == AF_INET6) {
        ngx_memzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_addr = in6addr_loopback;
        sin6.sin6_port = 0;
        sa = (struct sockaddr *) &sin6;
        socklen = sizeof(sin6);
#endif

    } else {
        ngx_close_socket(fd);
        return NULL;
    }

    if (bind(fd, sa, socklen) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, "bind() socks5 udp relay failed");
        ngx_close_socket(fd);
        return NULL;
    }

    if (ngx_nonblocking(fd) == -1) {
        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      ngx_socket_errno, ngx_nonblocking_n " failed");
        ngx_close_socket(fd);
        return NULL;
    }

    uc = ngx_get_connection(fd, ctx->session->connection->log);
    if (uc == NULL) {
        ngx_close_socket(fd);
        return NULL;
    }

    uc->data = ctx;
    uc->log = ctx->session->connection->log;
    uc->read->handler = handler;
    uc->write->handler = handler;

    if (ngx_add_event(uc->read, NGX_READ_EVENT, 0) != NGX_OK) {
        ngx_close_connection(uc);
        return NULL;
    }

    return uc;
}


static ngx_int_t
ngx_stream_trojan_socks5_udp_bind_addr(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *addr)
{
    ngx_connection_t      *c, *relay;
    struct sockaddr_in    *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6   *sin6;
#endif
    struct sockaddr_storage ss;
    socklen_t             socklen;

    c = ctx->session->connection;

    if (ngx_connection_local_sockaddr(c, NULL, 0) != NGX_OK) {
        return NGX_ERROR;
    }

    if (c->local_sockaddr->sa_family == AF_INET) {
        if (ctx->socks5_in_udp == NULL) {
            ctx->socks5_in_udp = ngx_stream_trojan_create_bound_udp_connection(
                ctx, AF_INET, ngx_stream_trojan_socks5_in_udp_read_handler);
        }
        relay = ctx->socks5_in_udp;
        if (relay == NULL) {
            return NGX_ERROR;
        }

        socklen = sizeof(ss);
        if (getsockname(relay->fd, (struct sockaddr *) &ss, &socklen) == -1) {
            return NGX_ERROR;
        }

        sin = (struct sockaddr_in *) &ss;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        addr->host_len = 4;
        addr->port = ntohs(sin->sin_port);
        ngx_memcpy(addr->host, &sin->sin_addr, 4);
        addr->wire_len = 1 + 4 + 2;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (c->local_sockaddr->sa_family == AF_INET6) {
        if (ctx->socks5_in_udp == NULL) {
            ctx->socks5_in_udp = ngx_stream_trojan_create_bound_udp_connection(
                ctx, AF_INET6, ngx_stream_trojan_socks5_in_udp_read_handler);
        }
        relay = ctx->socks5_in_udp;
        if (relay == NULL) {
            return NGX_ERROR;
        }

        socklen = sizeof(ss);
        if (getsockname(relay->fd, (struct sockaddr *) &ss, &socklen) == -1) {
            return NGX_ERROR;
        }

        sin6 = (struct sockaddr_in6 *) &ss;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        addr->host_len = 16;
        addr->port = ntohs(sin6->sin6_port);
        ngx_memcpy(addr->host, &sin6->sin6_addr, 16);
        addr->wire_len = 1 + 16 + 2;
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


static void
ngx_stream_trojan_process_udp_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t                         n;
    ngx_int_t                       rc;
    ngx_connection_t               *c;
    ngx_stream_trojan_udp_frame_t   frame;

    c = ctx->session->connection;

    for ( ;; ) {
        rc = ngx_stream_trojan_parse_udp_frame(ctx->udp_in, ctx->udp_in_len,
                                               &frame);

        if (rc == 0) {
            rc = ngx_stream_trojan_send_udp_frame(ctx, &frame);
            if (rc == NGX_AGAIN) {
                return;
            }

            if (rc != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            if (frame.wire_len < ctx->udp_in_len) {
                ngx_memmove(ctx->udp_in, ctx->udp_in + frame.wire_len,
                            ctx->udp_in_len - frame.wire_len);
            }
            ctx->udp_in_len -= frame.wire_len;
            continue;
        }

        if (ctx->udp_in_len == NGX_STREAM_TROJAN_UDP_BUFFER_SIZE)
        {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_REQUEST);
            return;
        }

        n = ngx_stream_trojan_recv(
            ctx, c, ctx->udp_in + ctx->udp_in_len,
            NGX_STREAM_TROJAN_UDP_BUFFER_SIZE - ctx->udp_in_len);

        if (n == NGX_AGAIN) {
            if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            }
            return;
        }

        if (n == 0 || n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        ctx->udp_in_len += (size_t) n;
    }
}


static ngx_int_t
ngx_stream_trojan_send_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    ngx_int_t                         rc;
    ngx_uint_t                        needs_resolve, ttl_cache;
    ngx_stream_trojan_outbound_t     *saved, *outbound;
    ngx_stream_trojan_route_cache_entry_t *cached;
    ngx_stream_trojan_udp_route_mapping_t *mapping;
    ngx_stream_trojan_route_addrs_t   resolved;

    saved = ctx->outbound;

    ngx_stream_trojan_route_resolve_target(ctx, &frame->addr);

    if (ctx->conf->route_enabled) {
        mapping = ngx_stream_trojan_udp_route_mapping_lookup(ctx,
                                                             &frame->addr);
        if (mapping != NULL && mapping->outbound != NULL) {
            ctx->outbound = mapping->outbound;
            ctx->udp_route_restore_outbound = saved;
            if (ngx_stream_trojan_udp_frame_blocked(ctx, frame)) {
                ctx->outbound = saved;
                ctx->udp_route_restore_outbound = NULL;
                return NGX_OK;
            }

            rc = ngx_stream_trojan_send_udp_frame_routed(ctx, frame);
            if (rc == NGX_AGAIN && ctx->udp_route_pending) {
                return rc;
            }

            ctx->outbound = saved;
            ctx->udp_route_restore_outbound = NULL;
            return rc;
        }

        cached = ngx_stream_trojan_route_cache_lookup(ctx->conf->route_cache,
                                                      &frame->addr);
        if (cached != NULL) {
            if (cached->ttl && cached->expires <= ngx_time()) {
                if (ngx_stream_trojan_route_resolver_kind(ctx)
                    != ngx_stream_trojan_route_resolver_nginx)
                {
                    goto udp_route_cache_miss;
                }

                ctx->outbound = cached->outbound;
                if (!cached->refreshing) {
                    ngx_stream_trojan_route_cache_start_refresh(ctx,
                                                                &frame->addr,
                                                                cached);
                }

                (void) ngx_stream_trojan_udp_route_mapping_insert(
                    ctx, &frame->addr, ctx->outbound, cached);
                ctx->udp_route_restore_outbound = saved;
                if (ngx_stream_trojan_udp_frame_blocked(ctx, frame)) {
                    ctx->outbound = saved;
                    ctx->udp_route_restore_outbound = NULL;
                    return NGX_OK;
                }
                rc = ngx_stream_trojan_send_udp_frame_routed(ctx, frame);
                if (rc == NGX_AGAIN && ctx->udp_route_pending) {
                    return rc;
                }
                ctx->outbound = saved;
                ctx->udp_route_restore_outbound = NULL;
                return rc;
            }

            ctx->outbound = cached->outbound;
            (void) ngx_stream_trojan_udp_route_mapping_insert(
                ctx, &frame->addr, ctx->outbound, cached);
            ctx->udp_route_restore_outbound = saved;
            if (ngx_stream_trojan_udp_frame_blocked(ctx, frame)) {
                ctx->outbound = saved;
                ctx->udp_route_restore_outbound = NULL;
                return NGX_OK;
            }
            rc = ngx_stream_trojan_send_udp_frame_routed(ctx, frame);
            if (rc == NGX_AGAIN && ctx->udp_route_pending) {
                return rc;
            }
            ctx->outbound = saved;
            ctx->udp_route_restore_outbound = NULL;
            return rc;
        }

udp_route_cache_miss:

        needs_resolve = 0;
        ttl_cache = 0;
        outbound = ngx_stream_trojan_select_outbound_now(ctx, &frame->addr,
                                                         NULL, 0, 0,
                                                         &needs_resolve,
                                                         &ttl_cache);
        if (outbound != NULL) {
            ctx->outbound = outbound;
            cached = ngx_stream_trojan_route_cache_insert(
                ctx->conf->route_cache, &frame->addr, outbound, ttl_cache, 0);
            (void) ngx_stream_trojan_udp_route_mapping_insert(
                ctx, &frame->addr, outbound, cached);
            ctx->udp_route_restore_outbound = saved;
            if (ngx_stream_trojan_udp_frame_blocked(ctx, frame)) {
                ctx->outbound = saved;
                ctx->udp_route_restore_outbound = NULL;
                return NGX_OK;
            }
            rc = ngx_stream_trojan_send_udp_frame_routed(ctx, frame);
            if (rc == NGX_AGAIN && ctx->udp_route_pending) {
                return rc;
            }
            ctx->outbound = saved;
            ctx->udp_route_restore_outbound = NULL;
            return rc;
        }

        if (needs_resolve) {
            if (ngx_stream_trojan_route_resolver_kind(ctx)
                != ngx_stream_trojan_route_resolver_nginx)
            {
                if (ngx_stream_trojan_route_system_resolve(ctx, &frame->addr,
                                                           &resolved)
                    != NGX_OK)
                {
                    ctx->outbound = saved;
                    return NGX_OK;
                }

                outbound = ngx_stream_trojan_select_outbound_now(
                    ctx, &frame->addr, resolved.addrs, resolved.naddrs, 1,
                    NULL, &ttl_cache);
                if (outbound != NULL) {
                    ctx->outbound = outbound;
                    cached = ngx_stream_trojan_route_cache_insert(
                        ctx->conf->route_cache, &frame->addr, outbound,
                        ttl_cache,
                        ngx_time() + NGX_STREAM_TROJAN_DEFAULT_ROUTE_CACHE_TTL);
                    (void) ngx_stream_trojan_udp_route_mapping_insert(
                        ctx, &frame->addr, outbound, cached);
                    ctx->udp_route_restore_outbound = saved;
                    if (ngx_stream_trojan_udp_frame_blocked(ctx, frame)) {
                        ctx->outbound = saved;
                        ctx->udp_route_restore_outbound = NULL;
                        return NGX_OK;
                    }
                    rc = ngx_stream_trojan_send_udp_frame_routed(ctx, frame);
                    if (rc == NGX_AGAIN && ctx->udp_route_pending) {
                        return rc;
                    }
                    ctx->outbound = saved;
                    ctx->udp_route_restore_outbound = NULL;
                    return rc;
                }

                ctx->outbound = saved;
                return NGX_OK;
            }

            return ngx_stream_trojan_start_udp_route_resolver(ctx, frame);
        }
    }

    ctx->udp_route_restore_outbound = saved;
    if (ngx_stream_trojan_udp_frame_blocked(ctx, frame)) {
        ctx->outbound = saved;
        ctx->udp_route_restore_outbound = NULL;
        return NGX_OK;
    }
    rc = ngx_stream_trojan_send_udp_frame_routed(ctx, frame);
    if (rc == NGX_AGAIN && ctx->udp_route_pending) {
        return rc;
    }
    ctx->outbound = saved;
    ctx->udp_route_restore_outbound = NULL;
    return rc;
}


static ngx_int_t
ngx_stream_trojan_send_udp_frame_routed(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    struct sockaddr_in   sin;
    char                 host[256];
    char                 service[6];
    int                  rc;
    struct addrinfo      hints;
    struct addrinfo     *res, *rp;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  sin6;
#endif
    struct sockaddr     *sa;
    socklen_t            socklen;
    ngx_uint_t           free_res;

    if (ngx_stream_trojan_outbound_type(ctx)
        == ngx_stream_trojan_outbound_socks5)
    {
        if (ctx->socks5_udp == NULL
            || ctx->socks5_udp_relay.sockaddr == NULL
            || ctx->socks5_udp_outbound != ctx->outbound)
        {
            if (ctx->udp_payload == NULL) {
                return NGX_ERROR;
            }

            ngx_memcpy(ctx->udp_payload, frame->payload, frame->payload_len);
            ctx->udp_route_addr = frame->addr;
            ctx->udp_route_payload_len = frame->payload_len;
            ctx->udp_route_pending = 1;
            ctx->udp_route_saved_outbound = ctx->outbound;

            if (frame->wire_len != 0 && frame->wire_len <= ctx->udp_in_len) {
                if (frame->wire_len < ctx->udp_in_len) {
                    ngx_memmove(ctx->udp_in, ctx->udp_in + frame->wire_len,
                                ctx->udp_in_len - frame->wire_len);
                }
                ctx->udp_in_len -= frame->wire_len;
            }

            ngx_stream_trojan_close_socks5_udp(ctx);
            ngx_stream_trojan_start_socks5_udp(ctx);
            return NGX_AGAIN;
        }

        return ngx_stream_trojan_send_socks5_udp_frame(ctx, frame);
    }

    res = NULL;
    free_res = 0;

    switch (frame->addr.type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        ngx_memzero(&sin, sizeof(sin));
        sin.sin_family = AF_INET;
        sin.sin_port = htons(frame->addr.port);
        ngx_memcpy(&sin.sin_addr, frame->addr.host, 4);
        sa = (struct sockaddr *) &sin;
        socklen = sizeof(sin);
        break;

#if (NGX_HAVE_INET6)
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        ngx_memzero(&sin6, sizeof(sin6));
        sin6.sin6_family = AF_INET6;
        sin6.sin6_port = htons(frame->addr.port);
        ngx_memcpy(&sin6.sin6_addr, frame->addr.host, 16);
        sa = (struct sockaddr *) &sin6;
        socklen = sizeof(sin6);
        break;
#endif

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (ngx_stream_trojan_use_nginx_resolver(
                frame->addr.type,
                ngx_stream_trojan_route_resolver(ctx) != NULL))
        {
            if (ngx_stream_trojan_start_resolver(ctx, &frame->addr,
                                                 ngx_stream_trojan_resolve_udp,
                                                 frame->payload,
                                                 frame->payload_len,
                                                 frame->wire_len)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            return NGX_AGAIN;
        }

        if (frame->addr.host_len == 0 || frame->addr.host_len >= sizeof(host)) {
            return NGX_ERROR;
        }

        ngx_memcpy(host, frame->addr.host, frame->addr.host_len);
        host[frame->addr.host_len] = '\0';
        ngx_snprintf((u_char *) service, sizeof(service), "%ui%Z",
                     (ngx_uint_t) frame->addr.port);

        ngx_memzero(&hints, sizeof(hints));
        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        rc = getaddrinfo(host, service, &hints, &res);
        if (rc != 0) {
            ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log, 0,
                          "getaddrinfo(\"%s\") failed: %s", host,
                          gai_strerror(rc));
            return NGX_ERROR;
        }

        rp = NULL;

        if (ngx_stream_trojan_current_ip_prefer(ctx)
            == NGX_STREAM_TROJAN_IP_PREFER_IPV4)
        {
            for (rp = res; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET) {
                    break;
                }
            }
        }

#if (NGX_HAVE_INET6)
        if (rp == NULL
            && ngx_stream_trojan_current_ip_prefer(ctx)
               == NGX_STREAM_TROJAN_IP_PREFER_IPV6)
        {
            for (rp = res; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET6) {
                    break;
                }
            }
        }
#endif

        if (rp == NULL) {
            for (rp = res; rp != NULL; rp = rp->ai_next) {
                if (rp->ai_family == AF_INET || rp->ai_family == AF_INET6) {
                    break;
                }
            }
        }

        if (rp != NULL) {
            if (rp->ai_family == AF_INET) {
                sa = rp->ai_addr;
                socklen = rp->ai_addrlen;
                free_res = 1;
                goto send;
            }

#if (NGX_HAVE_INET6)
            if (rp->ai_family == AF_INET6) {
                sa = rp->ai_addr;
                socklen = rp->ai_addrlen;
                free_res = 1;
                goto send;
            }
#endif
        }

        freeaddrinfo(res);
        return NGX_ERROR;

    default:
        return NGX_ERROR;
    }

send:
    rc = ngx_stream_trojan_send_udp_sockaddr(ctx, sa, socklen, frame->payload,
                                             frame->payload_len);
    if (free_res) {
        freeaddrinfo(res);
    }

    return rc;
}


static ngx_int_t
ngx_stream_trojan_send_socks5_udp_frame(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_frame_t *frame)
{
    size_t            written;

    if (ngx_stream_trojan_socks5_build_udp_packet(
            &frame->addr, frame->payload, frame->payload_len,
            ctx->udp_out,
            NGX_STREAM_TROJAN_SOCKS5_MAX_PACKET,
            &written)
        != 0)
    {
        return NGX_ERROR;
    }

    return ngx_stream_trojan_forward_socks5_udp_packet(ctx, ctx->udp_out,
                                                       written);
}


static ngx_int_t
ngx_stream_trojan_forward_socks5_udp_packet(ngx_stream_trojan_ctx_t *ctx,
    u_char *packet, size_t packet_len)
{
    ssize_t           n;
    ngx_connection_t *uc;

    uc = ctx->socks5_udp;
    if (uc == NULL || ctx->socks5_udp_relay.sockaddr == NULL) {
        return NGX_ERROR;
    }

    n = sendto(uc->fd, packet, packet_len, 0,
               ctx->socks5_udp_relay.sockaddr,
               ctx->socks5_udp_relay.socklen);

    if (n == -1) {
        ngx_err_t err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      err, "sendto() to socks5 udp relay failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_send_udp_resolved(ngx_stream_trojan_ctx_t *ctx,
    ngx_resolver_addr_t *addrs, ngx_uint_t naddrs, uint16_t port,
    const u_char *payload, uint16_t payload_len, ngx_uint_t ip_prefer)
{
    ngx_resolver_addr_t  *resolved;
    struct sockaddr      *sa;

    resolved = ngx_stream_trojan_resolver_pick_addr(addrs, naddrs, ip_prefer);
    if (resolved == NULL) {
        return NGX_ERROR;
    }

    sa = ngx_pnalloc(ctx->session->connection->pool, resolved->socklen);
    if (sa == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(sa, resolved->sockaddr, resolved->socklen);
    ngx_inet_set_port(sa, port);

    return ngx_stream_trojan_send_udp_sockaddr(ctx, sa, resolved->socklen,
                                               payload, payload_len);
}


static ngx_int_t
ngx_stream_trojan_send_udp_sockaddr(ngx_stream_trojan_ctx_t *ctx,
    struct sockaddr *sa, socklen_t socklen, const u_char *payload,
    uint16_t payload_len)
{
    ssize_t            n;
    ngx_connection_t  *uc;

    if (sa->sa_family == AF_INET) {
        if (ctx->udp4 == NULL) {
            ctx->udp4 = ngx_stream_trojan_create_udp_connection(
                ctx, AF_INET, ngx_stream_trojan_udp_read_handler);
            if (ctx->udp4 == NULL) {
                return NGX_ERROR;
            }
        }
        uc = ctx->udp4;

#if (NGX_HAVE_INET6)
    } else if (sa->sa_family == AF_INET6) {
        if (ctx->udp6 == NULL) {
            ctx->udp6 = ngx_stream_trojan_create_udp_connection(
                ctx, AF_INET6, ngx_stream_trojan_udp_read_handler);
            if (ctx->udp6 == NULL) {
                return NGX_ERROR;
            }
        }
        uc = ctx->udp6;
#endif

    } else {
        return NGX_ERROR;
    }

    n = sendto(uc->fd, payload, payload_len, 0, sa, socklen);
    if (n == -1) {
        ngx_err_t err = ngx_socket_errno;
        if (err == NGX_EAGAIN) {
            return NGX_OK;
        }

        ngx_log_error(NGX_LOG_ERR, ctx->session->connection->log,
                      err, "sendto() failed");
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_flush_udp_client(ngx_stream_trojan_ctx_t *ctx)
{
    ssize_t            n;
    ngx_connection_t  *c;
    ngx_buf_t         *b;

    c = ctx->session->connection;
    b = ctx->udp_pending_to_client;

    if (b == NULL) {
        return NGX_OK;
    }

    while (b->pos < b->last) {
        n = c->send(c, b->pos, b->last - b->pos);

        if (n == NGX_AGAIN) {
            if (ngx_handle_write_event(c->write, 0) != NGX_OK) {
                return NGX_ERROR;
            }
            return NGX_AGAIN;
        }

        if (n == NGX_ERROR) {
            return NGX_ERROR;
        }

        b->pos += n;
    }

    b->pos = b->start;
    b->last = b->start;
    ctx->udp_pending_to_client = NULL;

    return NGX_OK;
}


static void
ngx_stream_trojan_udp_client_write_handler(ngx_event_t *ev)
{
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
    }
}


static ngx_int_t
ngx_stream_trojan_sockaddr_to_addr(struct sockaddr *sa, socklen_t socklen,
    ngx_stream_trojan_addr_t *addr)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    ngx_memzero(addr, sizeof(*addr));

    if (sa->sa_family == AF_INET && socklen >= (socklen_t) sizeof(struct sockaddr_in)) {
        sin = (struct sockaddr_in *) sa;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        addr->host_len = 4;
        ngx_memcpy(addr->host, &sin->sin_addr, 4);
        addr->port = ntohs(sin->sin_port);
        addr->wire_len = 1 + 4 + 2;
        return NGX_OK;
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6 && socklen >= (socklen_t) sizeof(struct sockaddr_in6)) {
        sin6 = (struct sockaddr_in6 *) sa;
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        addr->host_len = 16;
        ngx_memcpy(addr->host, &sin6->sin6_addr, 16);
        addr->port = ntohs(sin6->sin6_port);
        addr->wire_len = 1 + 16 + 2;
        return NGX_OK;
    }
#endif

    return NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_loopback_sockaddr(struct sockaddr *sa)
{
    struct sockaddr_in   *sin;
#if (NGX_HAVE_INET6)
    struct sockaddr_in6  *sin6;
#endif

    if (sa->sa_family == AF_INET) {
        sin = (struct sockaddr_in *) sa;
        return sin->sin_addr.s_addr == htonl(INADDR_LOOPBACK);
    }

#if (NGX_HAVE_INET6)
    if (sa->sa_family == AF_INET6) {
        sin6 = (struct sockaddr_in6 *) sa;
        return IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr);
    }
#endif

    return 0;
}


static const char *
ngx_stream_trojan_local_proxy_name(ngx_stream_trojan_srv_conf_t *tscf)
{
    switch (tscf->local_proxy_type) {
    case ngx_stream_trojan_local_proxy_socks5:
        return "socks5";
    case ngx_stream_trojan_local_proxy_http_proxy:
        return "http_proxy";
    default:
        return tscf->socks5_enable ? "socks5" : "http_proxy";
    }
}


static ngx_stream_trojan_srv_conf_t *
ngx_stream_trojan_local_proxy_conflict(ngx_stream_conf_addr_t *addr,
    ngx_stream_core_srv_conf_t *current)
{
    ngx_uint_t                    s;
    ngx_stream_core_srv_conf_t  **servers;
    ngx_stream_trojan_srv_conf_t *tscf;

    servers = addr->servers.elts;

    for (s = 0; s < addr->servers.nelts; s++) {
        if (servers[s] == current) {
            continue;
        }

        tscf = servers[s]->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
        if (tscf != NULL
            && (tscf->socks5_enable || tscf->http_proxy_enable))
        {
            return tscf;
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_local_proxy_check_listens(ngx_conf_t *cf,
    ngx_stream_core_srv_conf_t *cscf, ngx_stream_trojan_srv_conf_t *tscf)
{
    const char                   *name;
    ngx_uint_t                    p, a, s, found;
    ngx_stream_conf_port_t       *port;
    ngx_stream_conf_addr_t       *addr;
    ngx_stream_core_srv_conf_t  **servers;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_trojan_srv_conf_t *conflict;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf->ports == NULL) {
        return NGX_ERROR;
    }

    found = 0;
    port = cmcf->ports->elts;

    for (p = 0; p < cmcf->ports->nelts; p++) {
        addr = port[p].addrs.elts;

        for (a = 0; a < port[p].addrs.nelts; a++) {
            servers = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {
                if (servers[s] != cscf) {
                    continue;
                }

                found = 1;
                name = ngx_stream_trojan_local_proxy_name(tscf);

                if (addr[a].servers.nelts != 1) {
                    conflict = ngx_stream_trojan_local_proxy_conflict(&addr[a],
                                                                      cscf);
                    name = ngx_stream_trojan_local_proxy_name(
                        conflict != NULL ? conflict : tscf);
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound listen %V conflicts "
                                       "with another stream server",
                                       name,
                                       &addr[a].opt.addr_text);
                    return NGX_ERROR;
                }

                if (port[p].type != SOCK_STREAM) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound requires TCP listen", name);
                    return NGX_ERROR;
                }

#if (NGX_STREAM_SSL)
                if (addr[a].opt.ssl) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound does not allow listen ssl",
                                       name);
                    return NGX_ERROR;
                }
#endif

                if (!ngx_stream_trojan_loopback_sockaddr(
                        addr[a].opt.sockaddr))
                {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                       "%s inbound only allows listen "
                                       "127.0.0.1 or [::1]", name);
                    return NGX_ERROR;
                }
            }
        }
    }

    return found ? NGX_OK : NGX_ERROR;
}


static ngx_int_t
ngx_stream_trojan_default_server_name(ngx_stream_core_srv_conf_t *cscf)
{
    ngx_stream_server_name_t  *name;

    if (cscf->server_names.nelts == 0) {
        return 1;
    }

    if (cscf->server_names.nelts != 1) {
        return 0;
    }

    name = cscf->server_names.elts;
    return name[0].name.len == 0;
}


static ngx_stream_trojan_srv_conf_t *
ngx_stream_trojan_find_trojan_server(ngx_conf_t *cf,
    ngx_stream_trojan_server_ref_t *ref, ngx_uint_t log_level)
{
    ngx_uint_t                    p, a, s, n, matches;
    ngx_stream_conf_port_t       *port;
    ngx_stream_conf_addr_t       *addr;
    ngx_stream_core_srv_conf_t  **servers, *cscf;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_server_name_t     *name;
    ngx_stream_trojan_srv_conf_t *tscf, *matched;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf->ports == NULL) {
        return NULL;
    }

    matches = 0;
    matched = NULL;
    port = cmcf->ports->elts;

    for (p = 0; p < cmcf->ports->nelts; p++) {
        if (port[p].port != ref->port || port[p].type != SOCK_STREAM) {
            continue;
        }

        addr = port[p].addrs.elts;
        for (a = 0; a < port[p].addrs.nelts; a++) {
            servers = addr[a].servers.elts;

            for (s = 0; s < addr[a].servers.nelts; s++) {
                cscf = servers[s];
                tscf = cscf->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
                if (tscf == NULL || !tscf->enable) {
                    continue;
                }

                if (ref->localhost) {
                    if (ngx_stream_trojan_default_server_name(cscf)) {
                        matches++;
                        matched = tscf;
                    }

                    continue;
                }

                name = cscf->server_names.elts;
                for (n = 0; n < cscf->server_names.nelts; n++) {
                    if (name[n].name.len == ref->host.len
                        && ngx_strncmp(name[n].name.data, ref->host.data,
                                       ref->host.len)
                           == 0)
                    {
                        matches++;
                        matched = tscf;
                        break;
                    }
                }
            }
        }
    }

    if (matches == 1) {
        return matched;
    }

    if (matches > 1) {
        if (ref->localhost) {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server localhost:%ui matches multiple "
                               "trojan servers without server_name",
                               (ngx_uint_t) ref->port);
        } else {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server \"%V:%ui\" matches multiple "
                               "trojan servers", &ref->host,
                               (ngx_uint_t) ref->port);
        }
    } else {
        if (ref->localhost) {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server localhost:%ui not found",
                               (ngx_uint_t) ref->port);
        } else {
            ngx_conf_log_error(log_level, cf, 0,
                               "trojan_server \"%V:%ui\" not found",
                               &ref->host, (ngx_uint_t) ref->port);
        }
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_postconfiguration(ngx_conf_t *cf)
{
    ngx_uint_t                    s, trojan_count;
    ngx_stream_core_srv_conf_t  **servers, *cscf;
    ngx_stream_core_main_conf_t  *cmcf;
    ngx_stream_trojan_srv_conf_t *tscf, *default_trojan, *target;
    ngx_stream_trojan_main_conf_t *tmcf;

    cmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_core_module);
    if (cmcf == NULL || cmcf->servers.nelts == 0) {
        return NGX_OK;
    }

    tmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_trojan_module);
    if (tmcf != NULL
        && ngx_stream_trojan_rules_compile(cf, &tmcf->rules) != NGX_OK)
    {
        return NGX_ERROR;
    }

    trojan_count = 0;
    default_trojan = NULL;
    servers = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = servers[s];
        tscf = cscf->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
        if (tscf != NULL) {
            tscf->core_srv_conf = cscf;
        }

        if (tscf != NULL
            && ngx_stream_trojan_rules_compile(cf, &tscf->rules) != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (tscf != NULL && tscf->enable) {
            if (ngx_stream_trojan_bind_outbound_matchers(cf, tscf)
                != NGX_OK)
            {
                return NGX_ERROR;
            }

            trojan_count++;
            default_trojan = tscf;
        }
    }

    for (s = 0; s < cmcf->servers.nelts; s++) {
        cscf = servers[s];
        tscf = cscf->ctx->srv_conf[ngx_stream_trojan_module.ctx_index];
        if (tscf != NULL) {
            tscf->core_srv_conf = cscf;
        }

        if (tscf == NULL
            || (!tscf->socks5_enable && !tscf->http_proxy_enable))
        {
            continue;
        }

        if (ngx_stream_trojan_local_proxy_check_listens(cf, cscf, tscf)
            != NGX_OK)
        {
            return NGX_ERROR;
        }

        if (tscf->enable) {
            tscf->effective = tscf;
            continue;
        }

        if (tscf->socks5_ref_set) {
            target = ngx_stream_trojan_find_trojan_server(cf,
                                                          &tscf->socks5_ref,
                                                          NGX_LOG_WARN);
            tscf->effective = target;
            continue;
        }

        if (trojan_count == 1) {
            tscf->effective = default_trojan;
            continue;
        }

        if (trojan_count == 0) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "local proxy inbound requires a trojan server");
        } else {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "local proxy inbound requires trojan_server when multiple "
                               "trojan servers are configured");
        }

        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_bind_outbound_matchers(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *tscf)
{
    ngx_uint_t                         i, route_enabled;
    ngx_stream_trojan_outbound_t      *outbound;
    ngx_stream_trojan_main_conf_t     *tmcf;
    ngx_stream_trojan_route_rules_t   *matcher;

    if (tscf->outbounds == NULL || tscf->outbounds->nelts == 0) {
        tscf->route_enabled = 0;
        return ngx_stream_trojan_create_internal_route_resolver(cf, tscf);
    }

    tmcf = ngx_stream_conf_get_module_main_conf(cf, ngx_stream_trojan_module);
    if (tmcf == NULL) {
        return NGX_ERROR;
    }

    route_enabled = 0;
    outbound = tscf->outbounds->elts;

    for (i = 0; i < tscf->outbounds->nelts; i++) {
        outbound[i].matcher = NULL;

        if (outbound[i].match_all || !outbound[i].has_rules) {
            break;
        }

        route_enabled = 1;

        matcher = ngx_stream_trojan_rules_find(&tscf->rules,
                                               &outbound[i].tag);
        if (matcher == NULL) {
            matcher = ngx_stream_trojan_rules_find(&tmcf->rules,
                                                   &outbound[i].tag);
        }

        outbound[i].matcher = matcher;
    }

    tscf->route_enabled = route_enabled;

    if (route_enabled && tscf->route_cache_size != 0) {
        if (ngx_stream_trojan_route_cache_init(cf, tscf) != NGX_OK) {
            return NGX_ERROR;
        }
    }

    if (ngx_stream_trojan_create_internal_route_resolver(cf, tscf) != NGX_OK) {
        return NGX_ERROR;
    }

    return NGX_OK;
}


static ngx_int_t
ngx_stream_trojan_route_cache_init(ngx_conf_t *cf,
    ngx_stream_trojan_srv_conf_t *tscf)
{
    ngx_uint_t                       n;
    ngx_stream_trojan_route_cache_t *cache;

    if (tscf->route_cache != NULL) {
        return NGX_OK;
    }

    cache = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_route_cache_t));
    if (cache == NULL) {
        return NGX_ERROR;
    }

    cache->size = tscf->route_cache_size;
    cache->buckets_n = 1;

    while (cache->buckets_n < cache->size * 2) {
        cache->buckets_n <<= 1;
    }

    cache->entries = ngx_pcalloc(cf->pool,
                                 cache->size * sizeof(*cache->entries));
    if (cache->entries == NULL) {
        return NGX_ERROR;
    }

    cache->buckets = ngx_pcalloc(cf->pool,
                                 cache->buckets_n * sizeof(*cache->buckets));
    if (cache->buckets == NULL) {
        return NGX_ERROR;
    }

    ngx_queue_init(&cache->lru);

    for (n = 0; n < cache->size; n++) {
        ngx_queue_init(&cache->entries[n].queue);
    }

    tscf->route_cache = cache;

    return NGX_OK;
}


static ngx_uint_t
ngx_stream_trojan_route_cache_hash(ngx_stream_trojan_addr_t *target)
{
    size_t      i;
    ngx_uint_t  hash;
    u_char      c;

    hash = 2166136261u;
    hash ^= target->type;
    hash *= 16777619u;
    hash ^= (u_char) (target->port >> 8);
    hash *= 16777619u;
    hash ^= (u_char) target->port;
    hash *= 16777619u;

    for (i = 0; i < target->host_len; i++) {
        c = target->host[i];
        if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
            c = ngx_tolower(c);
        }

        hash ^= c;
        hash *= 16777619u;
    }

    return hash;
}


static ngx_stream_trojan_route_cache_entry_t *
ngx_stream_trojan_route_cache_lookup(ngx_stream_trojan_route_cache_t *cache,
    ngx_stream_trojan_addr_t *target)
{
    size_t                                  i;
    ngx_uint_t                              hash, bucket;
    ngx_stream_trojan_route_cache_entry_t  *entry;

    if (cache == NULL || target->host_len == 0 || target->host_len > 255) {
        return NULL;
    }

    hash = ngx_stream_trojan_route_cache_hash(target);
    bucket = hash & (cache->buckets_n - 1);

    for (entry = cache->buckets[bucket]; entry != NULL; entry = entry->next) {
        if (!entry->valid || entry->hash != hash || entry->type != target->type
            || entry->host_len != target->host_len
            || entry->port != target->port)
        {
            continue;
        }

        if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
            for (i = 0; i < target->host_len; i++) {
                if (ngx_tolower(target->host[i]) != entry->host[i]) {
                    goto next;
                }
            }
        } else if (ngx_memcmp(entry->host, target->host, target->host_len)
                   != 0)
        {
            continue;
        }

        ngx_queue_remove(&entry->queue);
        ngx_queue_insert_head(&cache->lru, &entry->queue);

        return entry;

    next:
        continue;
    }

    return NULL;
}


static ngx_stream_trojan_route_cache_entry_t *
ngx_stream_trojan_route_cache_insert(ngx_stream_trojan_route_cache_t *cache,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_outbound_t *outbound,
    ngx_uint_t ttl, time_t expires)
{
    size_t                                  i;
    ngx_uint_t                              hash, bucket;
    ngx_queue_t                            *q;
    ngx_stream_trojan_route_cache_entry_t  *entry, **p;
    u_char                                  c;

    if (cache == NULL || outbound == NULL || target->host_len == 0
        || target->host_len > 255)
    {
        return NULL;
    }

    hash = ngx_stream_trojan_route_cache_hash(target);
    bucket = hash & (cache->buckets_n - 1);

    for (entry = cache->buckets[bucket]; entry != NULL; entry = entry->next) {
        if (entry->valid && entry->hash == hash && entry->type == target->type
            && entry->host_len == target->host_len
            && entry->port == target->port)
        {
            if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
                for (i = 0; i < target->host_len; i++) {
                    if (entry->host[i] != ngx_tolower(target->host[i])) {
                        goto next;
                    }
                }
            } else if (ngx_memcmp(entry->host, target->host, target->host_len)
                       != 0)
            {
                goto next;
            }

            ngx_stream_trojan_route_cache_update_entry(cache, entry,
                                                       outbound, ttl,
                                                       expires);
            ngx_queue_remove(&entry->queue);
            ngx_queue_insert_head(&cache->lru, &entry->queue);
            return entry;
        }

    next:
        continue;
    }

    if (cache->next_free < cache->size) {
        entry = &cache->entries[cache->next_free++];
    } else {
        q = ngx_queue_last(&cache->lru);
        entry = ngx_queue_data(q, ngx_stream_trojan_route_cache_entry_t,
                               queue);
        ngx_stream_trojan_route_cache_unlink_active(entry);
        ngx_queue_remove(q);

        p = &cache->buckets[entry->hash & (cache->buckets_n - 1)];
        while (*p != NULL) {
            if (*p == entry) {
                *p = entry->next;
                break;
            }

            p = &(*p)->next;
        }
    }

    ngx_memzero(entry, sizeof(*entry));
    ngx_queue_init(&entry->active_tcp);
    ngx_queue_init(&entry->active_udp);

    entry->valid = 1;
    entry->hash = hash;
    entry->generation = ++cache->generation;
    entry->type = target->type;
    entry->host_len = (uint8_t) target->host_len;
    entry->port = target->port;
    entry->outbound = outbound;
    entry->ttl = ttl ? 1 : 0;
    entry->expires = ttl ? expires : 0;

    if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        for (i = 0; i < target->host_len; i++) {
            c = target->host[i];
            entry->host[i] = ngx_tolower(c);
        }
    } else {
        ngx_memcpy(entry->host, target->host, target->host_len);
    }

    entry->next = cache->buckets[bucket];
    cache->buckets[bucket] = entry;
    ngx_queue_insert_head(&cache->lru, &entry->queue);

    return entry;
}


static void
ngx_stream_trojan_route_cache_update_entry(
    ngx_stream_trojan_route_cache_t *cache,
    ngx_stream_trojan_route_cache_entry_t *entry,
    ngx_stream_trojan_outbound_t *outbound, ngx_uint_t ttl, time_t expires)
{
    ngx_stream_trojan_outbound_t *old_outbound;

    if (cache == NULL || entry == NULL || !entry->valid) {
        return;
    }

    old_outbound = entry->outbound;

    if (old_outbound != outbound) {
        ngx_stream_trojan_route_mark_stale(entry, old_outbound);
    }

    entry->outbound = outbound;
    entry->ttl = ttl ? 1 : 0;
    entry->expires = ttl ? expires : 0;
    entry->refreshing = 0;
    entry->generation = ++cache->generation;
}


static void
ngx_stream_trojan_route_cache_unlink_active(
    ngx_stream_trojan_route_cache_entry_t *entry)
{
    ngx_queue_t                           *q;
    ngx_stream_trojan_ctx_t               *ctx;
    ngx_stream_trojan_udp_route_mapping_t *m;

    if (entry == NULL) {
        return;
    }

    while (!ngx_queue_empty(&entry->active_tcp)) {
        q = ngx_queue_head(&entry->active_tcp);
        ctx = ngx_queue_data(q, ngx_stream_trojan_ctx_t, route_queue);
        ngx_queue_remove(q);
        ngx_queue_init(q);
        ctx->route_linked = 0;
        ctx->route_stale = 0;
        ctx->route_entry = NULL;
        ctx->route_tracked_outbound = NULL;
    }

    while (!ngx_queue_empty(&entry->active_udp)) {
        q = ngx_queue_head(&entry->active_udp);
        m = ngx_queue_data(q, ngx_stream_trojan_udp_route_mapping_t, queue);
        ngx_queue_remove(q);
        ngx_queue_init(q);
        m->route_linked = 0;
        m->route_entry = NULL;
    }
}


static void
ngx_stream_trojan_route_mark_stale(
    ngx_stream_trojan_route_cache_entry_t *entry,
    ngx_stream_trojan_outbound_t *old_outbound)
{
    ngx_queue_t                           *q;
    ngx_stream_trojan_ctx_t               *ctx;
    ngx_stream_trojan_udp_route_mapping_t *m;

    if (entry == NULL || old_outbound == NULL) {
        return;
    }

    for (q = ngx_queue_head(&entry->active_tcp);
         q != ngx_queue_sentinel(&entry->active_tcp);
         q = ngx_queue_next(q))
    {
        ctx = ngx_queue_data(q, ngx_stream_trojan_ctx_t, route_queue);
        if (ctx->route_tracked_outbound == old_outbound) {
            ctx->route_stale = 1;
            ctx->route_last_active = ngx_current_msec;
            if (ctx->session != NULL
                && ctx->session->connection != NULL
                && ctx->session->connection->read != NULL)
            {
                ngx_add_timer(ctx->session->connection->read,
                              NGX_STREAM_TROJAN_ROUTE_DRAIN_TIMEOUT);
            }
        }
    }

    for (q = ngx_queue_head(&entry->active_udp);
         q != ngx_queue_sentinel(&entry->active_udp);
         q = ngx_queue_next(q))
    {
        m = ngx_queue_data(q, ngx_stream_trojan_udp_route_mapping_t, queue);
        if (m->outbound == old_outbound) {
            m->route_stale = 1;
            m->last_seen = ngx_current_msec;
        }
    }
}


static ngx_uint_t
ngx_stream_trojan_route_fast_drain_enabled(ngx_stream_trojan_ctx_t *ctx)
{
    return ctx != NULL
           && ctx->conf != NULL
           && ctx->conf->route_resolve == ngx_stream_trojan_route_resolve_lazy
           && ctx->conf->route_drain == ngx_stream_trojan_route_drain_fast;
}


static void
ngx_stream_trojan_route_track_tcp(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_route_cache_entry_t *entry)
{
    if (!ngx_stream_trojan_route_fast_drain_enabled(ctx)
        || entry == NULL || !entry->ttl || ctx->outbound == NULL)
    {
        return;
    }

    if (ctx->route_linked) {
        ngx_stream_trojan_route_untrack_tcp(ctx);
    }

    ngx_queue_insert_tail(&entry->active_tcp, &ctx->route_queue);
    ctx->route_entry = entry;
    ctx->route_tracked_outbound = ctx->outbound;
    ctx->route_last_active = ngx_current_msec;
    ctx->route_linked = 1;
    ctx->route_stale = 0;
}


static void
ngx_stream_trojan_route_untrack_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->route_linked) {
        return;
    }

    ngx_queue_remove(&ctx->route_queue);
    ngx_queue_init(&ctx->route_queue);
    ctx->route_linked = 0;
    ctx->route_stale = 0;
    ctx->route_entry = NULL;
    ctx->route_tracked_outbound = NULL;
}


static void
ngx_stream_trojan_route_touch_tcp(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx != NULL && ctx->route_linked) {
        ctx->route_last_active = ngx_current_msec;
    }
}


static ngx_uint_t
ngx_stream_trojan_route_tcp_idle(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx == NULL || ctx->client_buffer == NULL
        || ctx->upstream_buffer == NULL)
    {
        return 0;
    }

    if (ctx->pending_to_upstream != NULL
        && ctx->pending_to_upstream->pos < ctx->pending_to_upstream->last)
    {
        return 0;
    }

    if (ctx->pending_to_client != NULL
        && ctx->pending_to_client->pos < ctx->pending_to_client->last)
    {
        return 0;
    }

    return ctx->client_buffer->pos == ctx->client_buffer->last
           && ctx->upstream_buffer->pos == ctx->upstream_buffer->last;
}


static ngx_uint_t
ngx_stream_trojan_route_check_tcp_stale(ngx_stream_trojan_ctx_t *ctx)
{
    if (ctx == NULL || !ctx->route_linked || !ctx->route_stale) {
        return 0;
    }

    if (!ngx_stream_trojan_route_tcp_idle(ctx)) {
        ctx->route_last_active = ngx_current_msec;
        return 0;
    }

    if (ngx_current_msec - ctx->route_last_active
        >= NGX_STREAM_TROJAN_ROUTE_DRAIN_TIMEOUT)
    {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return 1;
    }

    return 0;
}


static void
ngx_stream_trojan_route_track_udp(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_udp_route_mapping_t *mapping,
    ngx_stream_trojan_route_cache_entry_t *entry)
{
    if (!ngx_stream_trojan_route_fast_drain_enabled(ctx)
        || mapping == NULL || entry == NULL || !entry->ttl)
    {
        return;
    }

    if (mapping->route_linked) {
        ngx_stream_trojan_route_untrack_udp(mapping);
    }

    ngx_queue_insert_tail(&entry->active_udp, &mapping->queue);
    mapping->route_entry = entry;
    mapping->route_linked = 1;
    mapping->route_stale = 0;
}


static void
ngx_stream_trojan_route_untrack_udp(
    ngx_stream_trojan_udp_route_mapping_t *mapping)
{
    if (mapping == NULL || !mapping->route_linked) {
        return;
    }

    ngx_queue_remove(&mapping->queue);
    ngx_queue_init(&mapping->queue);
    mapping->route_linked = 0;
    mapping->route_stale = 0;
    mapping->route_entry = NULL;
}


static ngx_uint_t
ngx_stream_trojan_udp_route_mapping_hash(ngx_stream_trojan_addr_t *target)
{
    return ngx_stream_trojan_route_cache_hash(target);
}


static ngx_int_t
ngx_stream_trojan_addr_equal(ngx_stream_trojan_addr_t *a,
    ngx_stream_trojan_addr_t *b)
{
    size_t i;

    if (a == NULL || b == NULL || a->type != b->type
        || a->host_len != b->host_len || a->port != b->port)
    {
        return 0;
    }

    if (a->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        for (i = 0; i < a->host_len; i++) {
            if (ngx_tolower(a->host[i]) != ngx_tolower(b->host[i])) {
                return 0;
            }
        }

        return 1;
    }

    return ngx_memcmp(a->host, b->host, a->host_len) == 0;
}


static ngx_stream_trojan_udp_route_mapping_t *
ngx_stream_trojan_udp_route_mapping_lookup(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target)
{
    ngx_uint_t                            hash, bucket;
    ngx_msec_t                            now;
    ngx_stream_trojan_udp_route_mapping_t *m, **p;

    if (ctx == NULL || target == NULL || target->host_len == 0
        || target->host_len > 255)
    {
        return NULL;
    }

    hash = ngx_stream_trojan_udp_route_mapping_hash(target);
    bucket = hash & (NGX_STREAM_TROJAN_UDP_ROUTE_MAPPING_BUCKETS - 1);
    now = ngx_current_msec;

    p = &ctx->udp_route_mappings[bucket];
    while (*p != NULL) {
        m = *p;

        if (m->route_stale
            && m->last_seen + NGX_STREAM_TROJAN_ROUTE_DRAIN_TIMEOUT < now)
        {
            ngx_stream_trojan_route_untrack_udp(m);
            *p = m->next;
            continue;
        }

        if (m->last_seen + ctx->conf->udp_timeout < now) {
            ngx_stream_trojan_route_untrack_udp(m);
            *p = m->next;
            continue;
        }

        if (m->hash == hash && ngx_stream_trojan_addr_equal(&m->target,
                                                            target))
        {
            m->last_seen = now;
            return m;
        }

        p = &m->next;
    }

    return NULL;
}


static ngx_int_t
ngx_stream_trojan_udp_route_mapping_insert(ngx_stream_trojan_ctx_t *ctx,
    ngx_stream_trojan_addr_t *target, ngx_stream_trojan_outbound_t *outbound,
    ngx_stream_trojan_route_cache_entry_t *entry)
{
    ngx_uint_t                             i, hash, bucket;
    ngx_stream_trojan_udp_route_mapping_t *m;

    if (ctx == NULL || target == NULL || outbound == NULL
        || target->host_len == 0 || target->host_len > 255)
    {
        return NGX_ERROR;
    }

    m = ngx_stream_trojan_udp_route_mapping_lookup(ctx, target);
    if (m != NULL) {
        ngx_stream_trojan_route_untrack_udp(m);
        m->outbound = outbound;
        m->last_seen = ngx_current_msec;
        ngx_stream_trojan_route_track_udp(ctx, m, entry);
        return NGX_OK;
    }

    m = ngx_pcalloc(ctx->session->connection->pool, sizeof(*m));
    if (m == NULL) {
        return NGX_ERROR;
    }

    hash = ngx_stream_trojan_udp_route_mapping_hash(target);
    bucket = hash & (NGX_STREAM_TROJAN_UDP_ROUTE_MAPPING_BUCKETS - 1);

    m->hash = hash;
    m->last_seen = ngx_current_msec;
    m->target = *target;
    m->outbound = outbound;
    ngx_queue_init(&m->queue);

    if (target->type == NGX_STREAM_TROJAN_ADDR_DOMAIN) {
        for (i = 0; i < target->host_len; i++) {
            m->target.host[i] = ngx_tolower(target->host[i]);
        }
    }

    m->next = ctx->udp_route_mappings[bucket];
    ctx->udp_route_mappings[bucket] = m;
    ngx_stream_trojan_route_track_udp(ctx, m, entry);

    return NGX_OK;
}


static void
ngx_stream_trojan_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                    n;
    size_t                     written;
    ngx_connection_t          *uc, *c;
    ngx_stream_trojan_ctx_t   *ctx;
    ngx_stream_trojan_addr_t   addr;
    struct sockaddr_storage    ss;
    socklen_t                  socklen;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }

    c = ctx->session->connection;

    for ( ;; ) {
        if (ngx_stream_trojan_flush_udp_client(ctx) != NGX_OK) {
            return;
        }

        socklen = sizeof(ss);
        n = recvfrom(uc->fd,
                     ctx->udp_payload,
                     NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD, 0,
                     (struct sockaddr *) &ss, &socklen);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_ERR, c->log, err, "recvfrom() failed");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        if (ngx_stream_trojan_sockaddr_to_addr((struct sockaddr *) &ss,
                                               socklen, &addr)
            != NGX_OK)
        {
            continue;
        }

        if (ngx_stream_trojan_pack_udp_frame(&addr, ctx->udp_payload,
                                             (uint16_t) n,
                                             ctx->udp_out,
                                             NGX_STREAM_TROJAN_UDP_BUFFER_SIZE,
                                             &written)
            != 0)
        {
            continue;
        }

        if (ctx->inbound_socks5) {
            if (!ctx->socks5_udp_client_set) {
                continue;
            }

            if (ctx->socks5_in_udp == NULL) {
                continue;
            }

            if (ngx_stream_trojan_socks5_build_udp_packet(
                    &addr, ctx->udp_payload, (uint16_t) n, ctx->udp_out,
                    NGX_STREAM_TROJAN_SOCKS5_MAX_PACKET, &written)
                != 0)
            {
                continue;
            }

            n = sendto(ctx->socks5_in_udp->fd, ctx->udp_out, written, 0,
                       (struct sockaddr *) &ctx->socks5_udp_client,
                       ctx->socks5_udp_client_socklen);
            if (n == -1 && ngx_socket_errno != NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                              "sendto() socks5 udp client failed");
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            continue;
        }

        ctx->udp_pending_to_client = ngx_stream_trojan_create_temp_buf(
            c->pool, written);
        if (ctx->udp_pending_to_client == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memcpy(ctx->udp_pending_to_client->last, ctx->udp_out, written);
        ctx->udp_pending_to_client->last += written;

        if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_socks5_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                         n;
    size_t                          written;
    ngx_connection_t               *uc, *c;
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_udp_frame_t   frame;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }

    c = ctx->session->connection;

    for ( ;; ) {
        if (ngx_stream_trojan_flush_udp_client(ctx) != NGX_OK) {
            return;
        }

        n = recvfrom(uc->fd, ctx->udp_out,
                     NGX_STREAM_TROJAN_SOCKS5_MAX_PACKET, 0, NULL, NULL);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_ERR, c->log, err,
                          "recvfrom() from socks5 udp relay failed");
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }

        if (ngx_stream_trojan_socks5_parse_udp_packet(ctx->udp_out,
                                                      (size_t) n, &frame)
            != 0)
        {
            continue;
        }

        if (ctx->inbound_socks5) {
            if (!ctx->socks5_udp_client_set || ctx->socks5_in_udp == NULL) {
                continue;
            }

            n = sendto(ctx->socks5_in_udp->fd, ctx->udp_out, (size_t) n, 0,
                       (struct sockaddr *) &ctx->socks5_udp_client,
                       ctx->socks5_udp_client_socklen);
            if (n == -1 && ngx_socket_errno != NGX_EAGAIN) {
                ngx_log_error(NGX_LOG_ERR, c->log, ngx_socket_errno,
                              "sendto() socks5 udp client failed");
                ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
                return;
            }

            continue;
        }

        ngx_memcpy(ctx->udp_payload, frame.payload, frame.payload_len);
        if (ngx_stream_trojan_pack_udp_frame(
                &frame.addr, ctx->udp_payload, frame.payload_len,
                ctx->udp_out, NGX_STREAM_TROJAN_UDP_BUFFER_SIZE,
                &written)
            != 0)
        {
            continue;
        }

        ctx->udp_pending_to_client = ngx_stream_trojan_create_temp_buf(
            c->pool, written);
        if (ctx->udp_pending_to_client == NULL) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
            return;
        }

        ngx_memcpy(ctx->udp_pending_to_client->last, ctx->udp_out, written);
        ctx->udp_pending_to_client->last += written;

        if (ngx_stream_trojan_flush_udp_client(ctx) == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_socks5_in_udp_read_handler(ngx_event_t *ev)
{
    ssize_t                         n;
    ngx_connection_t               *uc;
    ngx_stream_trojan_ctx_t        *ctx;
    ngx_stream_trojan_udp_frame_t   frame;
    struct sockaddr_storage         ss;
    socklen_t                       socklen;

    uc = ev->data;
    ctx = uc->data;

    if (ctx == NULL) {
        ngx_close_connection(uc);
        return;
    }

    for ( ;; ) {
        socklen = sizeof(ss);
        n = recvfrom(uc->fd, ctx->udp_out,
                     NGX_STREAM_TROJAN_SOCKS5_MAX_PACKET, 0,
                     (struct sockaddr *) &ss, &socklen);

        if (n == -1) {
            ngx_err_t err = ngx_socket_errno;
            if (err == NGX_EAGAIN) {
                break;
            }

            ngx_log_error(NGX_LOG_ERR, uc->log, err,
                          "recvfrom() socks5 udp relay failed");
            break;
        }

        if (ngx_stream_trojan_socks5_parse_udp_packet(ctx->udp_out,
                                                      (size_t) n, &frame)
            != 0)
        {
            continue;
        }

        if (ctx->resolver_ctx != NULL) {
            continue;
        }

        if (!ctx->socks5_udp_client_set) {
            ngx_memcpy(&ctx->socks5_udp_client, &ss, socklen);
            ctx->socks5_udp_client_socklen = socklen;
            ctx->socks5_udp_client_set = 1;
        } else if (ctx->socks5_udp_client_socklen != socklen
                   || ngx_memcmp(&ctx->socks5_udp_client, &ss, socklen) != 0)
        {
            continue;
        }

        if (!ctx->conf->route_enabled
            && ngx_stream_trojan_outbound_type(ctx)
            == ngx_stream_trojan_outbound_socks5)
        {
            (void) ngx_stream_trojan_forward_socks5_udp_packet(
                ctx, ctx->udp_out, (size_t) n);
            continue;
        }

        (void) ngx_stream_trojan_send_udp_frame(ctx, &frame);
    }

    if (ngx_handle_read_event(uc->read, 0) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, uc->log, 0,
                      "ngx_handle_read_event() socks5 udp relay failed");
    }
}


static void
ngx_stream_trojan_socks5_udp_control_handler(ngx_event_t *ev)
{
    u_char                    buf[128];
    ssize_t                   n;
    ngx_connection_t         *pc;
    ngx_stream_trojan_ctx_t  *ctx;

    pc = ev->data;
    ctx = pc->data;

    if (ctx == NULL) {
        ngx_close_connection(pc);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(pc, NGX_ETIMEDOUT,
                             "trojan socks5 udp control timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (pc->read->eof || pc->read->error || pc->write->error) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
        return;
    }

    for ( ;; ) {
        n = pc->recv(pc, buf, sizeof(buf));

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        if (n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_BAD_GATEWAY);
            return;
        }
    }

    if (ngx_handle_read_event(pc->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_socks5_in_udp_control_handler(ngx_event_t *ev)
{
    u_char                    buf[128];
    ssize_t                   n;
    ngx_connection_t         *c;
    ngx_stream_session_t     *s;
    ngx_stream_trojan_ctx_t  *ctx;

    c = ev->data;
    s = c->data;
    ctx = ngx_stream_get_module_ctx(s, ngx_stream_trojan_module);

    if (ctx == NULL) {
        ngx_stream_finalize_session(s, NGX_STREAM_INTERNAL_SERVER_ERROR);
        return;
    }

    if (ev->timedout) {
        ngx_connection_error(c, NGX_ETIMEDOUT,
                             "socks5 udp control timed out");
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    if (c->read->eof || c->read->error || c->write->error) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
        return;
    }

    for ( ;; ) {
        n = ngx_stream_trojan_recv(ctx, c, buf, sizeof(buf));

        if (n == NGX_AGAIN) {
            break;
        }

        if (n == 0) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }

        if (n == NGX_ERROR) {
            ngx_stream_trojan_finalize(ctx, NGX_STREAM_OK);
            return;
        }
    }

    if (ngx_handle_read_event(c->read, 0) != NGX_OK) {
        ngx_stream_trojan_finalize(ctx, NGX_STREAM_INTERNAL_SERVER_ERROR);
    }
}


static void
ngx_stream_trojan_finalize(ngx_stream_trojan_ctx_t *ctx, ngx_uint_t rc)
{
    ngx_stream_trojan_route_untrack_tcp(ctx);

    if (ctx->resolver_ctx) {
        ngx_resolve_name_done(ctx->resolver_ctx);
        ctx->resolver_ctx = NULL;
    }

    if (ctx->upstream) {
        ngx_close_connection(ctx->upstream);
        ctx->upstream = NULL;
    }

    if (ctx->udp4) {
        ngx_close_connection(ctx->udp4);
        ctx->udp4 = NULL;
    }

    if (ctx->socks5_udp) {
        ngx_close_connection(ctx->socks5_udp);
        ctx->socks5_udp = NULL;
    }

    if (ctx->socks5_in_udp) {
        ngx_close_connection(ctx->socks5_in_udp);
        ctx->socks5_in_udp = NULL;
    }

#if (NGX_HAVE_INET6)
    if (ctx->udp6) {
        ngx_close_connection(ctx->udp6);
        ctx->udp6 = NULL;
    }
#endif

    ngx_stream_finalize_session(ctx->session, rc);
}


static void *
ngx_stream_trojan_create_srv_conf(ngx_conf_t *cf)
{
    ngx_stream_trojan_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_stream_trojan_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->socks5_enable = NGX_CONF_UNSET;
    conf->http_proxy_enable = NGX_CONF_UNSET;
    conf->socks5_udp_enable = NGX_CONF_UNSET;
    conf->local_proxy_type = NGX_CONF_UNSET_UINT;
    conf->connect_timeout = NGX_CONF_UNSET_MSEC;
    conf->timeout = NGX_CONF_UNSET_MSEC;
    conf->udp_timeout = NGX_CONF_UNSET_MSEC;
    conf->buffer_size = NGX_CONF_UNSET_SIZE;
    conf->route_cache_size = NGX_CONF_UNSET_UINT;
    conf->route_resolve = NGX_CONF_UNSET_UINT;
    conf->route_drain = NGX_CONF_UNSET_UINT;
    conf->route_enabled = 0;

    return conf;
}


static char *
ngx_stream_trojan_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_stream_trojan_srv_conf_t *prev = parent;
    ngx_stream_trojan_srv_conf_t *conf = child;
    ngx_stream_trojan_outbound_t *dst, *src;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->socks5_enable, prev->socks5_enable, 0);
    ngx_conf_merge_value(conf->http_proxy_enable, prev->http_proxy_enable, 0);
    ngx_conf_merge_value(conf->socks5_udp_enable, prev->socks5_udp_enable, 0);
    ngx_conf_merge_uint_value(conf->local_proxy_type, prev->local_proxy_type,
                              ngx_stream_trojan_local_proxy_none);
    ngx_conf_merge_msec_value(conf->connect_timeout, prev->connect_timeout, 60000);
    ngx_conf_merge_msec_value(conf->timeout, prev->timeout, 600000);
    ngx_conf_merge_msec_value(conf->udp_timeout, prev->udp_timeout, 600000);
    ngx_conf_merge_size_value(conf->buffer_size, prev->buffer_size,
                              NGX_STREAM_TROJAN_DEFAULT_BUFFER_SIZE);
    ngx_conf_merge_uint_value(conf->route_cache_size, prev->route_cache_size,
                              NGX_STREAM_TROJAN_DEFAULT_ROUTE_CACHE_SIZE);
    ngx_conf_merge_uint_value(conf->route_resolve, prev->route_resolve,
                              ngx_stream_trojan_route_resolve_off);
    ngx_conf_merge_uint_value(conf->route_drain, prev->route_drain,
                              ngx_stream_trojan_route_drain_idle);

    if (conf->keys == NULL) {
        conf->keys = prev->keys;
    }

    if (conf->fallback == NULL) {
        conf->fallback = prev->fallback;
    }

    if (conf->outbounds == NULL && prev->outbounds != NULL) {
        conf->outbounds = ngx_array_create(cf->pool, prev->outbounds->nelts,
                                           sizeof(ngx_stream_trojan_outbound_t));
        if (conf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }

        dst = ngx_array_push_n(conf->outbounds, prev->outbounds->nelts);
        if (dst == NULL) {
            return NGX_CONF_ERROR;
        }

        src = prev->outbounds->elts;
        ngx_memcpy(dst, src,
                   prev->outbounds->nelts
                   * sizeof(ngx_stream_trojan_outbound_t));
    }

    conf->effective = conf->enable ? conf : NULL;

    if (conf->enable && (conf->keys == NULL || conf->keys->nelts == 0)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan is on but no trojan_password is configured");
        return NGX_CONF_ERROR;
    }

    if (conf->socks5_udp_enable && !conf->socks5_enable) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "socks5_udp requires socks5 on");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_socks5_on(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (tscf->socks5_enable
        && tscf->local_proxy_type == NGX_CONF_UNSET_UINT)
    {
        tscf->local_proxy_type = ngx_stream_trojan_local_proxy_socks5;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_http_proxy_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    char                        *rv;
    ngx_stream_core_srv_conf_t  *cscf;

    rv = ngx_conf_set_flag_slot(cf, cmd, conf);
    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (tscf->http_proxy_enable
        && tscf->local_proxy_type == NGX_CONF_UNSET_UINT)
    {
        tscf->local_proxy_type = ngx_stream_trojan_local_proxy_http_proxy;
    }

    cscf = ngx_stream_conf_get_module_srv_conf(cf, ngx_stream_core_module);
    cscf->handler = ngx_stream_trojan_handler;

    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_socks5_udp_on(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    return ngx_conf_set_flag_slot(cf, cmd, conf);
}


static char *
ngx_stream_trojan_trojan_server(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;
    ngx_str_t                   *value;

    if (tscf->socks5_ref_set) {
        return "is duplicate";
    }

    value = cf->args->elts;

    if (ngx_stream_trojan_parse_server_ref(cf, &value[1], &tscf->socks5_ref)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    tscf->socks5_ref_set = 1;

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_route_cache(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_int_t   n;
    ngx_str_t  *value;

    value = cf->args->elts;

    if (tscf->route_cache_size != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (value[1].len == sizeof("off") - 1
        && ngx_strncmp(value[1].data, "off", value[1].len) == 0)
    {
        tscf->route_cache_size = 0;
        (void) cmd;
        return NGX_CONF_OK;
    }

    n = ngx_atoi(value[1].data, value[1].len);
    if (n == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid route_cache value \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    tscf->route_cache_size = (ngx_uint_t) n;

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_route_resolve(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (tscf->route_resolve != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (value[1].len == sizeof("off") - 1
        && ngx_strncmp(value[1].data, "off", value[1].len) == 0)
    {
        tscf->route_resolve = ngx_stream_trojan_route_resolve_off;
        (void) cmd;
        return NGX_CONF_OK;
    }

    if (value[1].len == sizeof("literal") - 1
        && ngx_strncmp(value[1].data, "literal", value[1].len) == 0)
    {
        tscf->route_resolve = ngx_stream_trojan_route_resolve_literal;
        (void) cmd;
        return NGX_CONF_OK;
    }

    if (value[1].len == sizeof("lazy") - 1
        && ngx_strncmp(value[1].data, "lazy", value[1].len) == 0)
    {
        tscf->route_resolve = ngx_stream_trojan_route_resolve_lazy;
        (void) cmd;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid route_resolve value \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_stream_trojan_route_drain(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_str_t  *value;

    value = cf->args->elts;

    if (tscf->route_drain != NGX_CONF_UNSET_UINT) {
        return "is duplicate";
    }

    if (value[1].len == sizeof("idle") - 1
        && ngx_strncmp(value[1].data, "idle", value[1].len) == 0)
    {
        tscf->route_drain = ngx_stream_trojan_route_drain_idle;
        (void) cmd;
        return NGX_CONF_OK;
    }

    if (value[1].len == sizeof("fast") - 1
        && ngx_strncmp(value[1].data, "fast", value[1].len) == 0)
    {
        tscf->route_drain = ngx_stream_trojan_route_drain_fast;
        (void) cmd;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "invalid route_drain value \"%V\"", &value[1]);
    return NGX_CONF_ERROR;
}


static char *
ngx_stream_trojan_password(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_uint_t                i;
    ngx_str_t                *value;
    ngx_stream_trojan_key_t  *key;

    if (tscf->keys == NULL) {
        tscf->keys = ngx_array_create(cf->pool, 2, sizeof(ngx_stream_trojan_key_t));
        if (tscf->keys == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    value = cf->args->elts;

    for (i = 1; i < cf->args->nelts; i++) {
        key = ngx_array_push(tscf->keys);
        if (key == NULL) {
            return NGX_CONF_ERROR;
        }

        if (ngx_stream_trojan_make_key_len(value[i].data, value[i].len,
                                           key->data)
            != 0)
        {
            return NGX_CONF_ERROR;
        }
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_fallback(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    ngx_url_t    u;
    ngx_str_t   *value;

    if (tscf->fallback != NULL) {
        return "is duplicate";
    }

    value = cf->args->elts;

    ngx_memzero(&u, sizeof(ngx_url_t));
    u.url = value[1];
    u.default_port = 80;
    u.no_resolve = 0;

    if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
        if (u.err) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "%s in trojan_fallback \"%V\"", u.err, &u.url);
        }
        return NGX_CONF_ERROR;
    }

    if (u.naddrs < 1) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "trojan_fallback \"%V\" resolved to no addresses",
                           &u.url);
        return NGX_CONF_ERROR;
    }

    tscf->fallback = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
    if (tscf->fallback == NULL) {
        return NGX_CONF_ERROR;
    }

    *tscf->fallback = u.addrs[0];

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_outbounds(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t   *tscf = conf;
    ngx_stream_trojan_outbound_t   *outbound;

    char         *rv;
    ngx_str_t    *value;
    ngx_conf_t    save;

    value = cf->args->elts;

    if (ngx_strcmp(value[1].data, "socks5") != 0) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "unsupported outbounds type \"%V\"", &value[1]);
        return NGX_CONF_ERROR;
    }

    if (tscf->outbounds == NULL) {
        tscf->outbounds = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_outbound_t));
        if (tscf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    outbound = ngx_array_push(tscf->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_stream_trojan_outbound_init(outbound,
                                    ngx_stream_trojan_outbound_socks5);

    save = *cf;
    cf->handler = ngx_stream_trojan_outbounds_block;
    cf->handler_conf = outbound;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (outbound->socks5_server == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 requires server");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_password.len != 0
        && outbound->socks5_username.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 password requires username");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_username.len != 0
        && outbound->socks5_password.data == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds socks5 username requires password");
        return NGX_CONF_ERROR;
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_outbound_direct_directive(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    char                         *rv;
    ngx_conf_t                    save;
    ngx_str_t                    *value;
    ngx_stream_trojan_outbound_t *outbound;

    value = cf->args->elts;

    if (tscf->outbounds == NULL) {
        tscf->outbounds = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_outbound_t));
        if (tscf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    outbound = ngx_array_push(tscf->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_stream_trojan_outbound_init(outbound,
                                    ngx_stream_trojan_outbound_direct);

    if (cf->args->nelts == 2
        && ngx_stream_trojan_outbound_set_tag(cf, outbound, &value[1])
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_stream_trojan_outbounds_block;
    cf->handler_conf = outbound;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    (void) cmd;
    return rv;
}


static char *
ngx_stream_trojan_outbound_socks5_directive(ngx_conf_t *cf,
    ngx_command_t *cmd, void *conf)
{
    ngx_stream_trojan_srv_conf_t *tscf = conf;

    char                         *rv;
    ngx_conf_t                    save;
    ngx_str_t                    *value;
    ngx_stream_trojan_outbound_t *outbound;

    value = cf->args->elts;

    if (tscf->outbounds == NULL) {
        tscf->outbounds = ngx_array_create(
            cf->pool, 2, sizeof(ngx_stream_trojan_outbound_t));
        if (tscf->outbounds == NULL) {
            return NGX_CONF_ERROR;
        }
    }

    outbound = ngx_array_push(tscf->outbounds);
    if (outbound == NULL) {
        return NGX_CONF_ERROR;
    }

    ngx_stream_trojan_outbound_init(outbound,
                                    ngx_stream_trojan_outbound_socks5);

    if (cf->args->nelts == 2
        && ngx_stream_trojan_outbound_set_tag(cf, outbound, &value[1])
           != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    save = *cf;
    cf->handler = ngx_stream_trojan_outbounds_block;
    cf->handler_conf = outbound;

    rv = ngx_conf_parse(cf, NULL);

    *cf = save;

    if (rv != NGX_CONF_OK) {
        return rv;
    }

    if (outbound->socks5_server == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 requires server");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_password.len != 0
        && outbound->socks5_username.len == 0)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 password requires username");
        return NGX_CONF_ERROR;
    }

    if (outbound->socks5_username.len != 0
        && outbound->socks5_password.data == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "outbounds_socks5 username requires password");
        return NGX_CONF_ERROR;
    }

    (void) cmd;
    return NGX_CONF_OK;
}


static char *
ngx_stream_trojan_outbounds_block(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_stream_trojan_outbound_t *outbound = conf;

    ngx_url_t   u;
    ngx_str_t  *value;

    value = cf->args->elts;

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "server") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_socks5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "server is only allowed in outbounds_socks5");
            return NGX_CONF_ERROR;
        }

        if (outbound->socks5_server != NULL) {
            return "duplicate socks5 server";
        }

        ngx_memzero(&u, sizeof(ngx_url_t));
        u.url = value[1];
        u.default_port = 1080;
        u.no_resolve = 0;

        if (ngx_parse_url(cf->pool, &u) != NGX_OK) {
            if (u.err) {
                ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                   "%s in outbounds socks5 server \"%V\"",
                                   u.err, &u.url);
            }
            return NGX_CONF_ERROR;
        }

        if (u.naddrs < 1) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "outbounds socks5 server \"%V\" resolved "
                               "to no addresses", &u.url);
            return NGX_CONF_ERROR;
        }

        outbound->socks5_server = ngx_pcalloc(cf->pool, sizeof(ngx_addr_t));
        if (outbound->socks5_server == NULL) {
            return NGX_CONF_ERROR;
        }

        *outbound->socks5_server = u.addrs[0];
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "username") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_socks5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "username is only allowed in outbounds_socks5");
            return NGX_CONF_ERROR;
        }

        if (outbound->socks5_username.data != NULL) {
            return "duplicate socks5 username";
        }

        if (value[1].len == 0 || value[1].len > 255) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "socks5 username length must be 1..255");
            return NGX_CONF_ERROR;
        }

        outbound->socks5_username = value[1];
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "password") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_socks5) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "password is only allowed in outbounds_socks5");
            return NGX_CONF_ERROR;
        }

        if (outbound->socks5_password.data != NULL) {
            return "duplicate socks5 password";
        }

        if (value[1].len > 255) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "socks5 password length must be <= 255");
            return NGX_CONF_ERROR;
        }

        outbound->socks5_password = value[1];
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "ip_prefer") == 0) {
        if (outbound->type != ngx_stream_trojan_outbound_direct) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "ip_prefer is only allowed in outbounds_direct");
            return NGX_CONF_ERROR;
        }

        if (outbound->ip_prefer_set) {
            return "duplicate ip_prefer";
        }

        if (ngx_stream_trojan_parse_ip_prefer(&value[1],
                                              &outbound->ip_prefer)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid ip_prefer value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        outbound->ip_prefer_set = 1;
        return NGX_CONF_OK;
    }

    if (cf->args->nelts == 2 && ngx_strcmp(value[0].data, "block") == 0) {
        if (outbound->block_set) {
            return "duplicate block";
        }

        if (ngx_stream_trojan_parse_block(&value[1], &outbound->block)
            != NGX_OK)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "invalid block value \"%V\"", &value[1]);
            return NGX_CONF_ERROR;
        }

        if (outbound->type == ngx_stream_trojan_outbound_socks5
            && outbound->block == ngx_stream_trojan_block_all)
        {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "block all is only allowed for outbounds_direct");
            return NGX_CONF_ERROR;
        }

        outbound->block_set = 1;
        return NGX_CONF_OK;
    }

    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                       "unknown directive \"%V\" in outbounds block",
                       &value[0]);

    (void) cmd;
    return NGX_CONF_ERROR;
}
