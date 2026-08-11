#ifndef _NGX_STREAM_TROJAN_PROTOCOL_H_INCLUDED_
#define _NGX_STREAM_TROJAN_PROTOCOL_H_INCLUDED_

#include <stddef.h>
#include <stdint.h>

#define NGX_STREAM_TROJAN_KEY_LEN 56
#define NGX_STREAM_TROJAN_CRLF_LEN 2
#define NGX_STREAM_TROJAN_PREFIX_LEN \
    (NGX_STREAM_TROJAN_KEY_LEN + NGX_STREAM_TROJAN_CRLF_LEN)
#define NGX_STREAM_TROJAN_MAX_ADDR_LEN (1 + 1 + 255 + 2)
#define NGX_STREAM_TROJAN_MAX_UDP_PAYLOAD 65535

#define NGX_STREAM_TROJAN_CMD_CONNECT 0x01
#define NGX_STREAM_TROJAN_CMD_ASSOCIATE 0x03

#define NGX_STREAM_TROJAN_ADDR_IPV4 0x01
#define NGX_STREAM_TROJAN_ADDR_DOMAIN 0x03
#define NGX_STREAM_TROJAN_ADDR_IPV6 0x04

typedef struct {
    uint8_t type;
    uint8_t host[255];
    size_t host_len;
    uint16_t port;
    size_t wire_len;
} ngx_stream_trojan_addr_t;

typedef struct {
    ngx_stream_trojan_addr_t addr;
    uint16_t payload_len;
    const uint8_t *payload;
    size_t wire_len;
} ngx_stream_trojan_udp_frame_t;

int ngx_stream_trojan_make_key(const char *password, uint8_t out[NGX_STREAM_TROJAN_KEY_LEN]);
int ngx_stream_trojan_make_key_len(const uint8_t *password, size_t password_len,
    uint8_t out[NGX_STREAM_TROJAN_KEY_LEN]);
int ngx_stream_trojan_key_equal(const uint8_t *a, const uint8_t *b);
int ngx_stream_trojan_parse_addr(const uint8_t *buf, size_t len, ngx_stream_trojan_addr_t *addr);
int ngx_stream_trojan_normalize_ip_literal(ngx_stream_trojan_addr_t *addr);
int ngx_stream_trojan_addr_to_text(const ngx_stream_trojan_addr_t *addr, char *out, size_t out_len);
int ngx_stream_trojan_parse_udp_frame(const uint8_t *buf, size_t len, ngx_stream_trojan_udp_frame_t *frame);
int ngx_stream_trojan_pack_udp_frame(const ngx_stream_trojan_addr_t *addr, const uint8_t *payload,
    uint16_t payload_len, uint8_t *out, size_t out_len, size_t *written);
int ngx_stream_trojan_use_nginx_resolver(uint8_t addr_type, int resolver_configured);
const uint8_t *ngx_stream_trojan_default_fallback_response(size_t *len);
const uint8_t *ngx_stream_trojan_default_h2_fallback_response(size_t *len);

#endif
