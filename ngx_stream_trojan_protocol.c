#include "ngx_stream_trojan_protocol.h"

#include <arpa/inet.h>
#include <stdio.h>
#include <string.h>

static const uint8_t ngx_stream_trojan_hex[] = "0123456789abcdef";
static const uint8_t ngx_stream_trojan_503_response[] =
    "HTTP/1.1 503 Service Unavailable\r\n"
    "Content-Type: text/plain\r\n"
    "Content-Length: 19\r\n"
    "Connection: close\r\n"
    "\r\n"
    "Service Unavailable";

static const uint8_t ngx_stream_trojan_h2_503_response[] = {
    /* Empty server SETTINGS. */
    0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00,

    /* Stream 1 HEADERS with END_HEADERS. */
    0x00, 0x00, 0x17, 0x01, 0x04, 0x00, 0x00, 0x00, 0x01,
    0x08, 0x03, '5', '0', '3',
    0x0f, 0x10, 0x0a, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n',
    0x0f, 0x0d, 0x02, '1', '9',

    /* Stream 1 DATA with END_STREAM. */
    0x00, 0x00, 0x13, 0x00, 0x01, 0x00, 0x00, 0x00, 0x01,
    'S', 'e', 'r', 'v', 'i', 'c', 'e', ' ', 'U', 'n', 'a', 'v', 'a', 'i',
    'l', 'a', 'b', 'l', 'e',

    /* GOAWAY after stream 1 with NO_ERROR. */
    0x00, 0x00, 0x08, 0x07, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00
};

#define NGX_STREAM_TROJAN_SHA224_DIGEST_LEN 28
#define NGX_STREAM_TROJAN_SHA256_BLOCK_LEN 64

typedef struct {
    uint32_t h[8];
    uint8_t block[NGX_STREAM_TROJAN_SHA256_BLOCK_LEN];
    uint64_t len;
    size_t block_len;
} ngx_stream_trojan_sha224_ctx_t;

static uint32_t
ngx_stream_trojan_rotr32(uint32_t v, unsigned n)
{
    return (v >> n) | (v << (32 - n));
}

static uint32_t
ngx_stream_trojan_load_be32(const uint8_t *p)
{
    return ((uint32_t) p[0] << 24) | ((uint32_t) p[1] << 16)
           | ((uint32_t) p[2] << 8) | (uint32_t) p[3];
}

static void
ngx_stream_trojan_store_be32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t) (v >> 24);
    p[1] = (uint8_t) (v >> 16);
    p[2] = (uint8_t) (v >> 8);
    p[3] = (uint8_t) v;
}

static const uint32_t ngx_stream_trojan_sha256_k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

static void
ngx_stream_trojan_sha224_init(ngx_stream_trojan_sha224_ctx_t *ctx)
{
    ctx->h[0] = 0xc1059ed8;
    ctx->h[1] = 0x367cd507;
    ctx->h[2] = 0x3070dd17;
    ctx->h[3] = 0xf70e5939;
    ctx->h[4] = 0xffc00b31;
    ctx->h[5] = 0x68581511;
    ctx->h[6] = 0x64f98fa7;
    ctx->h[7] = 0xbefa4fa4;
    ctx->len = 0;
    ctx->block_len = 0;
}

static void
ngx_stream_trojan_sha256_transform(ngx_stream_trojan_sha224_ctx_t *ctx, const uint8_t block[64])
{
    uint32_t w[64];
    uint32_t a, b, c, d, e, f, g, h, t1, t2;
    size_t i;

    for (i = 0; i < 16; i++) {
        w[i] = ngx_stream_trojan_load_be32(block + i * 4);
    }

    for (i = 16; i < 64; i++) {
        uint32_t s0 = ngx_stream_trojan_rotr32(w[i - 15], 7)
                      ^ ngx_stream_trojan_rotr32(w[i - 15], 18)
                      ^ (w[i - 15] >> 3);
        uint32_t s1 = ngx_stream_trojan_rotr32(w[i - 2], 17)
                      ^ ngx_stream_trojan_rotr32(w[i - 2], 19)
                      ^ (w[i - 2] >> 10);
        w[i] = w[i - 16] + s0 + w[i - 7] + s1;
    }

    a = ctx->h[0];
    b = ctx->h[1];
    c = ctx->h[2];
    d = ctx->h[3];
    e = ctx->h[4];
    f = ctx->h[5];
    g = ctx->h[6];
    h = ctx->h[7];

    for (i = 0; i < 64; i++) {
        uint32_t s1 = ngx_stream_trojan_rotr32(e, 6)
                      ^ ngx_stream_trojan_rotr32(e, 11)
                      ^ ngx_stream_trojan_rotr32(e, 25);
        uint32_t ch = (e & f) ^ (~e & g);
        uint32_t s0 = ngx_stream_trojan_rotr32(a, 2)
                      ^ ngx_stream_trojan_rotr32(a, 13)
                      ^ ngx_stream_trojan_rotr32(a, 22);
        uint32_t maj = (a & b) ^ (a & c) ^ (b & c);

        t1 = h + s1 + ch + ngx_stream_trojan_sha256_k[i] + w[i];
        t2 = s0 + maj;
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t1 + t2;
    }

    ctx->h[0] += a;
    ctx->h[1] += b;
    ctx->h[2] += c;
    ctx->h[3] += d;
    ctx->h[4] += e;
    ctx->h[5] += f;
    ctx->h[6] += g;
    ctx->h[7] += h;
}

static void
ngx_stream_trojan_sha224_update(ngx_stream_trojan_sha224_ctx_t *ctx, const uint8_t *data, size_t len)
{
    size_t n;

    ctx->len += (uint64_t) len * 8;

    while (len > 0) {
        n = NGX_STREAM_TROJAN_SHA256_BLOCK_LEN - ctx->block_len;
        if (n > len) {
            n = len;
        }

        memcpy(ctx->block + ctx->block_len, data, n);
        ctx->block_len += n;
        data += n;
        len -= n;

        if (ctx->block_len == NGX_STREAM_TROJAN_SHA256_BLOCK_LEN) {
            ngx_stream_trojan_sha256_transform(ctx, ctx->block);
            ctx->block_len = 0;
        }
    }
}

static void
ngx_stream_trojan_sha224_final(ngx_stream_trojan_sha224_ctx_t *ctx,
    uint8_t out[NGX_STREAM_TROJAN_SHA224_DIGEST_LEN])
{
    uint8_t len_buf[8];
    size_t i;

    for (i = 0; i < 8; i++) {
        len_buf[7 - i] = (uint8_t) (ctx->len >> (i * 8));
    }

    ctx->block[ctx->block_len++] = 0x80;

    if (ctx->block_len > 56) {
        memset(ctx->block + ctx->block_len, 0, 64 - ctx->block_len);
        ngx_stream_trojan_sha256_transform(ctx, ctx->block);
        ctx->block_len = 0;
    }

    memset(ctx->block + ctx->block_len, 0, 56 - ctx->block_len);
    memcpy(ctx->block + 56, len_buf, sizeof(len_buf));
    ngx_stream_trojan_sha256_transform(ctx, ctx->block);

    for (i = 0; i < 7; i++) {
        ngx_stream_trojan_store_be32(out + i * 4, ctx->h[i]);
    }
}

static void
ngx_stream_trojan_sha224(const uint8_t *data, size_t len,
    uint8_t out[NGX_STREAM_TROJAN_SHA224_DIGEST_LEN])
{
    ngx_stream_trojan_sha224_ctx_t ctx;

    ngx_stream_trojan_sha224_init(&ctx);
    ngx_stream_trojan_sha224_update(&ctx, data, len);
    ngx_stream_trojan_sha224_final(&ctx, out);
}

int
ngx_stream_trojan_make_key(const char *password, uint8_t out[NGX_STREAM_TROJAN_KEY_LEN])
{
    if (password == NULL || out == NULL) {
        return -1;
    }

    return ngx_stream_trojan_make_key_len((const uint8_t *) password,
                                          strlen(password), out);
}

int
ngx_stream_trojan_make_key_len(const uint8_t *password, size_t password_len,
    uint8_t out[NGX_STREAM_TROJAN_KEY_LEN])
{
    uint8_t digest[NGX_STREAM_TROJAN_SHA224_DIGEST_LEN];
    size_t i;

    if (password == NULL || out == NULL) {
        return -1;
    }

    ngx_stream_trojan_sha224(password, password_len, digest);

    for (i = 0; i < NGX_STREAM_TROJAN_SHA224_DIGEST_LEN; i++) {
        out[i * 2] = ngx_stream_trojan_hex[digest[i] >> 4];
        out[i * 2 + 1] = ngx_stream_trojan_hex[digest[i] & 0x0f];
    }

    return 0;
}

int
ngx_stream_trojan_key_equal(const uint8_t *a, const uint8_t *b)
{
    uint8_t diff = 0;
    size_t i;

    if (a == NULL || b == NULL) {
        return 0;
    }

    for (i = 0; i < NGX_STREAM_TROJAN_KEY_LEN; i++) {
        diff |= a[i] ^ b[i];
    }

    return diff == 0;
}

int
ngx_stream_trojan_parse_addr(const uint8_t *buf, size_t len, ngx_stream_trojan_addr_t *addr)
{
    size_t host_len;
    size_t wire_len;

    if (buf == NULL || addr == NULL || len < 1) {
        return -1;
    }

    memset(addr, 0, sizeof(*addr));
    addr->type = buf[0];

    switch (addr->type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        host_len = 4;
        wire_len = 1 + host_len + 2;
        if (len < wire_len) {
            return -1;
        }
        memcpy(addr->host, buf + 1, host_len);
        addr->host_len = host_len;
        addr->port = (uint16_t) ((buf[1 + host_len] << 8) | buf[1 + host_len + 1]);
        addr->wire_len = wire_len;
        return 0;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        if (len < 2) {
            return -1;
        }
        host_len = buf[1];
        wire_len = 1 + 1 + host_len + 2;
        if (host_len == 0 || len < wire_len) {
            return -1;
        }
        memcpy(addr->host, buf + 2, host_len);
        addr->host_len = host_len;
        addr->port = (uint16_t) ((buf[2 + host_len] << 8) | buf[2 + host_len + 1]);
        addr->wire_len = wire_len;
        return 0;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        host_len = 16;
        wire_len = 1 + host_len + 2;
        if (len < wire_len) {
            return -1;
        }
        memcpy(addr->host, buf + 1, host_len);
        addr->host_len = host_len;
        addr->port = (uint16_t) ((buf[1 + host_len] << 8) | buf[1 + host_len + 1]);
        addr->wire_len = wire_len;
        return 0;

    default:
        return -1;
    }
}


static int
ngx_stream_trojan_tail_has_colon(const uint8_t *data, size_t len)
{
    size_t i, start;

    start = len > 5 ? len - 5 : 0;

    for (i = start; i < len; i++) {
        if (data[i] == ':') {
            return 1;
        }
    }

    return 0;
}


int
ngx_stream_trojan_normalize_ip_literal(ngx_stream_trojan_addr_t *addr)
{
    uint8_t last;
    struct in_addr in;
    struct in6_addr in6;
    char text[INET6_ADDRSTRLEN];

    if (addr == NULL || addr->type != NGX_STREAM_TROJAN_ADDR_DOMAIN
        || addr->host_len == 0 || addr->host_len >= sizeof(text))
    {
        return 0;
    }

    last = addr->host[addr->host_len - 1];

    if ((last < '0' || last > '9')
        && !ngx_stream_trojan_tail_has_colon(addr->host, addr->host_len))
    {
        return 0;
    }

    memcpy(text, addr->host, addr->host_len);
    text[addr->host_len] = '\0';

    if (inet_pton(AF_INET, text, &in) == 1) {
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV4;
        memcpy(addr->host, &in, sizeof(in));
        addr->host_len = sizeof(in);
        addr->wire_len = 1 + addr->host_len + 2;
        return 1;
    }

    if (inet_pton(AF_INET6, text, &in6) == 1) {
        addr->type = NGX_STREAM_TROJAN_ADDR_IPV6;
        memcpy(addr->host, &in6, sizeof(in6));
        addr->host_len = sizeof(in6);
        addr->wire_len = 1 + addr->host_len + 2;
        return 1;
    }

    return 0;
}


int
ngx_stream_trojan_addr_to_text(const ngx_stream_trojan_addr_t *addr, char *out, size_t out_len)
{
    int n;

    if (addr == NULL || out == NULL || out_len == 0) {
        return -1;
    }

    switch (addr->type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
        if (addr->host_len != 4) {
            return -1;
        }
        n = snprintf(out, out_len, "%u.%u.%u.%u:%u",
                     addr->host[0], addr->host[1], addr->host[2], addr->host[3],
                     (unsigned) addr->port);
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        n = snprintf(out, out_len, "%.*s:%u", (int) addr->host_len,
                     (const char *) addr->host, (unsigned) addr->port);
        break;

    case NGX_STREAM_TROJAN_ADDR_IPV6:
        if (addr->host_len != 16) {
            return -1;
        }
        n = snprintf(out, out_len,
                     "[%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x]:%u",
                     addr->host[0], addr->host[1], addr->host[2], addr->host[3],
                     addr->host[4], addr->host[5], addr->host[6], addr->host[7],
                     addr->host[8], addr->host[9], addr->host[10], addr->host[11],
                     addr->host[12], addr->host[13], addr->host[14], addr->host[15],
                     (unsigned) addr->port);
        break;

    default:
        return -1;
    }

    if (n < 0 || (size_t) n >= out_len) {
        return -1;
    }

    return 0;
}

int
ngx_stream_trojan_parse_udp_frame(const uint8_t *buf, size_t len, ngx_stream_trojan_udp_frame_t *frame)
{
    size_t pos;
    size_t wire_len;

    if (buf == NULL || frame == NULL) {
        return -1;
    }

    memset(frame, 0, sizeof(*frame));

    if (ngx_stream_trojan_parse_addr(buf, len, &frame->addr) != 0) {
        return -1;
    }

    pos = frame->addr.wire_len;
    if (len < pos + 4) {
        return -1;
    }

    frame->payload_len = (uint16_t) ((buf[pos] << 8) | buf[pos + 1]);
    if (buf[pos + 2] != '\r' || buf[pos + 3] != '\n') {
        return -1;
    }

    wire_len = pos + 4 + frame->payload_len;
    if (len < wire_len) {
        return -1;
    }

    frame->payload = buf + pos + 4;
    frame->wire_len = wire_len;
    return 0;
}

int
ngx_stream_trojan_pack_udp_frame(const ngx_stream_trojan_addr_t *addr, const uint8_t *payload,
    uint16_t payload_len, uint8_t *out, size_t out_len, size_t *written)
{
    size_t pos = 0;

    if (addr == NULL || out == NULL || written == NULL || (payload_len > 0 && payload == NULL)) {
        return -1;
    }

    if (out_len < addr->wire_len + 4 + payload_len) {
        return -1;
    }

    out[pos++] = addr->type;

    switch (addr->type) {
    case NGX_STREAM_TROJAN_ADDR_IPV4:
    case NGX_STREAM_TROJAN_ADDR_IPV6:
        memcpy(out + pos, addr->host, addr->host_len);
        pos += addr->host_len;
        break;

    case NGX_STREAM_TROJAN_ADDR_DOMAIN:
        out[pos++] = (uint8_t) addr->host_len;
        memcpy(out + pos, addr->host, addr->host_len);
        pos += addr->host_len;
        break;

    default:
        return -1;
    }

    out[pos++] = (uint8_t) (addr->port >> 8);
    out[pos++] = (uint8_t) addr->port;
    out[pos++] = (uint8_t) (payload_len >> 8);
    out[pos++] = (uint8_t) payload_len;
    out[pos++] = '\r';
    out[pos++] = '\n';

    if (payload_len > 0) {
        memcpy(out + pos, payload, payload_len);
        pos += payload_len;
    }

    *written = pos;
    return 0;
}


int
ngx_stream_trojan_use_nginx_resolver(uint8_t addr_type, int resolver_configured)
{
    return addr_type == NGX_STREAM_TROJAN_ADDR_DOMAIN && resolver_configured;
}


const uint8_t *
ngx_stream_trojan_default_fallback_response(size_t *len)
{
    if (len != NULL) {
        *len = sizeof(ngx_stream_trojan_503_response) - 1;
    }

    return ngx_stream_trojan_503_response;
}


const uint8_t *
ngx_stream_trojan_default_h2_fallback_response(size_t *len)
{
    if (len != NULL) {
        *len = sizeof(ngx_stream_trojan_h2_503_response);
    }

    return ngx_stream_trojan_h2_503_response;
}
