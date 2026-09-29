/**
 * @file    r2_common.h
 * @brief   Definiciones y utilidades compartidas por el emisor y el receptor
 *          de tramas de capa 2 (Enlace de Datos, modelo OSI).
 *
 * Formato de la trama (Ethernet II con EtherType experimental 0x88B5):
 *
 *   +-----------+-----------+-----------+---------------------------+
 *   | MAC dest. | MAC orig. | EtherType |          PAYLOAD          |
 *   |  6 bytes  |  6 bytes  |  2 bytes  |     46 .. 1500 bytes      |
 *   +-----------+-----------+-----------+---------------------------+
 *
 * Estructura del PAYLOAD (protocolo propio de la práctica):
 *
 *   +-------------+----------------+--------------+----------------+
 *   | LONGITUD    | MENSAJE        | CRC-32       | RELLENO (0x00) |
 *   | 2 B (BE)    | LONGITUD bytes | 4 B (BE)     | hasta 46 bytes |
 *   +-------------+----------------+--------------+----------------+
 *   |<---- región útil: se le aplica el ruido ---->|
 *
 * El CRC-32 se calcula sobre [LONGITUD || MENSAJE] ANTES de aplicar ruido,
 * de modo que el receptor pueda detectar los bits que el canal invirtió.
 */
#ifndef R2_COMMON_H
#define R2_COMMON_H

#include <stddef.h>
#include <stdint.h>

/* ------------------------------------------------------------------ */
/* Constantes de la trama Ethernet II                                  */
/* ------------------------------------------------------------------ */
#define R2_MAC_LEN        6u      /**< Bytes de una dirección MAC.            */
#define R2_ETH_HDR_LEN    14u     /**< MAC dst (6) + MAC src (6) + tipo (2).  */
#define R2_MIN_PAYLOAD    46u     /**< Payload mínimo (sin FCS) de Ethernet.  */
#define R2_MAX_PAYLOAD    1500u   /**< MTU de Ethernet: payload máximo.       */
#define R2_MAX_FRAME      (R2_ETH_HDR_LEN + R2_MAX_PAYLOAD)

/** EtherType "IEEE 802 Local Experimental 1": reservado para pruebas. */
#define R2_ETHERTYPE      0x88B5u

/** Filtro BPF que deja pasar únicamente nuestras tramas. */
#define R2_BPF_FILTER     "ether proto 0x88b5"

/* ------------------------------------------------------------------ */
/* Estructura del payload propio                                       */
/* ------------------------------------------------------------------ */
#define R2_LEN_FIELD      2u      /**< Bytes del campo LONGITUD.              */
#define R2_CRC_FIELD      4u      /**< Bytes del campo CRC-32.                */
#define R2_MAX_MSG_LEN    (R2_MAX_PAYLOAD - R2_LEN_FIELD - R2_CRC_FIELD)

/** Cabecera Ethernet II, empaquetada para mapearla directo sobre el buffer. */
typedef struct __attribute__((packed)) {
    uint8_t  dst[R2_MAC_LEN];     /**< MAC destino.                           */
    uint8_t  src[R2_MAC_LEN];     /**< MAC origen.                            */
    uint16_t ethertype;           /**< Tipo de protocolo (orden de red).      */
} r2_eth_header_t;

/** Generador pseudoaleatorio xorshift64* (reproducible mediante semilla). */
typedef struct {
    uint64_t state;
} r2_rng_t;

/** Resultado de validar un payload recibido. */
typedef enum {
    R2_PARSE_OK = 0,              /**< Longitud coherente y CRC correcto.     */
    R2_PARSE_TOO_SHORT,           /**< Payload menor al mínimo del protocolo. */
    R2_PARSE_BAD_LENGTH,          /**< El campo LONGITUD excede la trama.     */
    R2_PARSE_BAD_CRC              /**< El CRC no coincide: hubo ruido.        */
} r2_parse_status_t;

/* ------------------------------------------------------------------ */
/* API                                                                 */
/* ------------------------------------------------------------------ */

/** Calcula el CRC-32 IEEE 802.3 (polinomio reflejado 0xEDB88320). */
uint32_t r2_crc32(const uint8_t *data, size_t len);

/** Inicializa el generador con @p seed (una semilla 0 se sustituye). */
void r2_rng_seed(r2_rng_t *rng, uint64_t seed);

/** Devuelve un número uniforme en el intervalo [0, 1). */
double r2_rng_uniform(r2_rng_t *rng);

/**
 * Simula un canal binario simétrico (BSC): cada bit de @p buf se invierte
 * de forma independiente con probabilidad @p p.
 *
 * @param positions      Arreglo opcional donde se guardan los índices de bit
 *                       invertidos (0 = MSB del primer byte). Puede ser NULL.
 * @param max_positions  Capacidad de @p positions.
 * @return Número total de bits invertidos.
 */
size_t r2_apply_noise(uint8_t *buf, size_t len, double p, r2_rng_t *rng,
                      size_t *positions, size_t max_positions);

/**
 * Convierte bytes a una cadena de bits ("01001000 01101111 ...").
 * @return Número de caracteres escritos (sin contar el NUL final).
 */
size_t r2_bits_to_string(const uint8_t *buf, size_t len,
                         char *out, size_t out_size);

/** Interpreta "aa:bb:cc:dd:ee:ff". @return 0 si es válida, -1 si no. */
int r2_parse_mac(const char *text, uint8_t mac[R2_MAC_LEN]);

/** Escribe la MAC como "aa:bb:cc:dd:ee:ff" (requiere 18 bytes en @p out). */
void r2_format_mac(const uint8_t mac[R2_MAC_LEN], char out[18]);

/** Obtiene la MAC de la interfaz @p iface. @return 0 en éxito, -1 en error. */
int r2_get_iface_mac(const char *iface, uint8_t mac[R2_MAC_LEN]);

/**
 * Construye el payload [LONGITUD || MENSAJE || CRC-32 || RELLENO].
 *
 * @param[out] useful_len  Bytes de la región útil (sin relleno).
 * @param[out] total_len   Bytes totales del payload (con relleno).
 * @return 0 en éxito, -1 si los argumentos son inválidos o no caben.
 */
int r2_build_payload(const uint8_t *msg, size_t msg_len,
                     uint8_t *payload, size_t payload_size,
                     size_t *useful_len, size_t *total_len);

/**
 * Valida un payload recibido.
 *
 * @param[out] msg_len   Longitud declarada del mensaje (válida si status es
 *                       OK o BAD_CRC).
 * @param[out] crc_rx    CRC-32 recibido en la trama.
 * @param[out] crc_calc  CRC-32 recalculado localmente.
 */
r2_parse_status_t r2_parse_payload(const uint8_t *payload, size_t payload_len,
                                   size_t *msg_len, uint32_t *crc_rx,
                                   uint32_t *crc_calc);

#endif /* R2_COMMON_H */
