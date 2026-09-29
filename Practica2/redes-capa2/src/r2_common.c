/**
 * @file    r2_common.c
 * @brief   Implementación de las utilidades compartidas (CRC, ruido, bits,
 *          direcciones MAC y armado/validación del payload).
 */
#include "r2_common.h"

#include <ifaddrs.h>
#include <netpacket/packet.h>
#include <stdio.h>
#include <string.h>

/* ------------------------------------------------------------------ */
/* CRC-32                                                              */
/* ------------------------------------------------------------------ */

uint32_t r2_crc32(const uint8_t *data, size_t len)
{
    uint32_t crc = 0xFFFFFFFFu;               /* Valor inicial estándar.   */

    for (size_t i = 0; i < len; i++) {
        crc ^= data[i];                       /* Mezcla el byte actual.    */
        for (int bit = 0; bit < 8; bit++) {
            /* Si el bit menos significativo es 1, se aplica el polinomio. */
            uint32_t mask = 0u - (crc & 1u);  /* 0x00000000 ó 0xFFFFFFFF.  */
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;                              /* Complemento final.        */
}

/* ------------------------------------------------------------------ */
/* Generador pseudoaleatorio y canal ruidoso                           */
/* ------------------------------------------------------------------ */

void r2_rng_seed(r2_rng_t *rng, uint64_t seed)
{
    /* xorshift no admite el estado 0: se sustituye por una constante. */
    rng->state = (seed != 0u) ? seed : 0x9E3779B97F4A7C15ull;
}

/** Avanza el estado y devuelve 64 bits pseudoaleatorios (xorshift64*). */
static uint64_t rng_next(r2_rng_t *rng)
{
    uint64_t x = rng->state;
    x ^= x >> 12;
    x ^= x << 25;
    x ^= x >> 27;
    rng->state = x;
    return x * 0x2545F4914F6CDD1Dull;
}

double r2_rng_uniform(r2_rng_t *rng)
{
    /* Se usan los 53 bits altos: es la precisión de la mantisa de double. */
    return (double)(rng_next(rng) >> 11) * (1.0 / 9007199254740992.0);
}

size_t r2_apply_noise(uint8_t *buf, size_t len, double p, r2_rng_t *rng,
                      size_t *positions, size_t max_positions)
{
    size_t flips = 0;

    if (buf == NULL || rng == NULL || p <= 0.0) {
        return 0;
    }

    for (size_t bit_index = 0; bit_index < len * 8u; bit_index++) {
        if (r2_rng_uniform(rng) < p) {
            /* Bit 0 = MSB del primer byte (mismo orden que r2_bits_to_string). */
            buf[bit_index / 8u] ^= (uint8_t)(0x80u >> (bit_index % 8u));
            if (positions != NULL && flips < max_positions) {
                positions[flips] = bit_index;
            }
            flips++;
        }
    }
    return flips;
}

/* ------------------------------------------------------------------ */
/* Representación en bits                                              */
/* ------------------------------------------------------------------ */

size_t r2_bits_to_string(const uint8_t *buf, size_t len,
                         char *out, size_t out_size)
{
    size_t pos = 0;

    if (out == NULL || out_size == 0u) {
        return 0;
    }

    for (size_t i = 0; i < len; i++) {
        /* Cada byte ocupa 8 caracteres + 1 separador; se reserva el NUL. */
        if (pos + 9u + 1u > out_size) {
            break;                            /* Salida truncada, nunca desborda. */
        }
        for (int b = 7; b >= 0; b--) {
            out[pos++] = (char)('0' + ((buf[i] >> b) & 1u));
        }
        out[pos++] = ' ';
    }
    if (pos > 0u) {
        pos--;                                /* Elimina el último espacio.  */
    }
    out[pos] = '\0';
    return pos;
}

/* ------------------------------------------------------------------ */
/* Direcciones MAC                                                     */
/* ------------------------------------------------------------------ */

int r2_parse_mac(const char *text, uint8_t mac[R2_MAC_LEN])
{
    unsigned int v[R2_MAC_LEN];
    char tail = '\0';

    if (text == NULL) {
        return -1;
    }
    /* El %c final detecta basura después de la MAC ("aa:...:ffXYZ"). */
    int n = sscanf(text, "%2x:%2x:%2x:%2x:%2x:%2x%c",
                   &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail);
    if (n != (int)R2_MAC_LEN) {
        return -1;
    }
    for (size_t i = 0; i < R2_MAC_LEN; i++) {
        mac[i] = (uint8_t)v[i];
    }
    return 0;
}

void r2_format_mac(const uint8_t mac[R2_MAC_LEN], char out[18])
{
    snprintf(out, 18, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

int r2_get_iface_mac(const char *iface, uint8_t mac[R2_MAC_LEN])
{
    struct ifaddrs *list = NULL;
    int rc = -1;

    if (getifaddrs(&list) != 0) {
        return -1;
    }
    for (const struct ifaddrs *it = list; it != NULL; it = it->ifa_next) {
        if (it->ifa_addr == NULL || it->ifa_addr->sa_family != AF_PACKET) {
            continue;                         /* Solo interesa la familia L2. */
        }
        if (strcmp(it->ifa_name, iface) != 0) {
            continue;
        }
        const struct sockaddr_ll *ll = (const struct sockaddr_ll *)it->ifa_addr;
        if (ll->sll_halen == R2_MAC_LEN) {
            memcpy(mac, ll->sll_addr, R2_MAC_LEN);
            rc = 0;
        }
        break;
    }
    freeifaddrs(list);
    return rc;
}

/* ------------------------------------------------------------------ */
/* Payload                                                             */
/* ------------------------------------------------------------------ */

/** Escribe @p v en 4 bytes, big-endian (orden de red). */
static void put_be32(uint8_t *dst, uint32_t v)
{
    dst[0] = (uint8_t)(v >> 24);
    dst[1] = (uint8_t)(v >> 16);
    dst[2] = (uint8_t)(v >> 8);
    dst[3] = (uint8_t)v;
}

/** Lee 4 bytes big-endian. */
static uint32_t get_be32(const uint8_t *src)
{
    return ((uint32_t)src[0] << 24) | ((uint32_t)src[1] << 16) |
           ((uint32_t)src[2] << 8)  |  (uint32_t)src[3];
}

int r2_build_payload(const uint8_t *msg, size_t msg_len,
                     uint8_t *payload, size_t payload_size,
                     size_t *useful_len, size_t *total_len)
{
    if (msg == NULL || payload == NULL || useful_len == NULL ||
        total_len == NULL || msg_len == 0u || msg_len > R2_MAX_MSG_LEN) {
        return -1;
    }

    const size_t useful = R2_LEN_FIELD + msg_len + R2_CRC_FIELD;
    const size_t total  = (useful < R2_MIN_PAYLOAD) ? R2_MIN_PAYLOAD : useful;
    if (total > payload_size) {
        return -1;
    }

    payload[0] = (uint8_t)(msg_len >> 8);     /* LONGITUD (big-endian).      */
    payload[1] = (uint8_t)(msg_len & 0xFFu);
    memcpy(payload + R2_LEN_FIELD, msg, msg_len);

    /* El CRC protege LONGITUD + MENSAJE. */
    put_be32(payload + R2_LEN_FIELD + msg_len,
             r2_crc32(payload, R2_LEN_FIELD + msg_len));

    /* Relleno con ceros hasta alcanzar el payload mínimo de Ethernet. */
    memset(payload + useful, 0, total - useful);

    *useful_len = useful;
    *total_len  = total;
    return 0;
}

r2_parse_status_t r2_parse_payload(const uint8_t *payload, size_t payload_len,
                                   size_t *msg_len, uint32_t *crc_rx,
                                   uint32_t *crc_calc)
{
    if (payload == NULL || payload_len < R2_LEN_FIELD + R2_CRC_FIELD) {
        return R2_PARSE_TOO_SHORT;
    }

    const size_t declared = ((size_t)payload[0] << 8) | payload[1];

    /* Si el ruido alteró LONGITUD, podría apuntar fuera de la trama. */
    if (declared + R2_LEN_FIELD + R2_CRC_FIELD > payload_len) {
        return R2_PARSE_BAD_LENGTH;
    }

    *msg_len  = declared;
    *crc_rx   = get_be32(payload + R2_LEN_FIELD + declared);
    *crc_calc = r2_crc32(payload, R2_LEN_FIELD + declared);

    return (*crc_rx == *crc_calc) ? R2_PARSE_OK : R2_PARSE_BAD_CRC;
}
