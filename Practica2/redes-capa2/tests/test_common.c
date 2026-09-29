/**
 * @file    test_common.c
 * @brief   Pruebas unitarias mínimas de las utilidades compartidas.
 *          No requiere privilegios ni red:  make check
 */
#include <stdio.h>
#include <string.h>

#include "r2_common.h"

static int failures = 0;

#define CHECK(cond, name)                                               \
    do {                                                                \
        if (cond) { printf("[ OK ] %s\n", name); }                      \
        else      { printf("[FAIL] %s\n", name); failures++; }          \
    } while (0)

int main(void)
{
    /* Vector de prueba estándar del CRC-32: "123456789" -> 0xCBF43926. */
    CHECK(r2_crc32((const uint8_t *)"123456789", 9) == 0xCBF43926u, "CRC-32 vector estandar");

    /* Cadena de bits de 'H' (0x48) y 'o' (0x6F). */
    char bits[64];
    r2_bits_to_string((const uint8_t *)"Ho", 2, bits, sizeof(bits));
    CHECK(strcmp(bits, "01001000 01101111") == 0, "bytes -> cadena de bits");

    /* MAC: ida y vuelta, y rechazo de entradas inválidas. */
    uint8_t mac[R2_MAC_LEN];
    char txt[18];
    CHECK(r2_parse_mac("02:42:ac:11:00:02", mac) == 0, "parse MAC valida");
    r2_format_mac(mac, txt);
    CHECK(strcmp(txt, "02:42:ac:11:00:02") == 0, "format MAC");
    CHECK(r2_parse_mac("02:42:ac:11:00", mac) != 0, "rechaza MAC corta");
    CHECK(r2_parse_mac("02:42:ac:11:00:02:99", mac) != 0, "rechaza MAC larga");

    /* Payload: construir y validar sin ruido. */
    const char *msg = "Hola Redes2027-1";
    uint8_t payload[R2_MAX_PAYLOAD];
    size_t useful = 0, total = 0, mlen = 0;
    uint32_t rx = 0, calc = 0;
    CHECK(r2_build_payload((const uint8_t *)msg, strlen(msg), payload,
                           sizeof(payload), &useful, &total) == 0, "build payload");
    CHECK(useful == 22u && total == R2_MIN_PAYLOAD, "tamanos: 2+16+4 = 22 utiles, relleno a 46");
    CHECK(r2_parse_payload(payload, total, &mlen, &rx, &calc) == R2_PARSE_OK &&
          mlen == strlen(msg), "parse payload limpio");

    /* Un solo bit invertido debe detectarse siempre. */
    payload[5] ^= 0x01u;
    CHECK(r2_parse_payload(payload, total, &mlen, &rx, &calc) != R2_PARSE_OK,
          "detecta 1 bit invertido");
    payload[5] ^= 0x01u;

    /* Ruido: p = 0 no cambia nada; p = 1 invierte todos los bits. */
    r2_rng_t rng;
    r2_rng_seed(&rng, 1234);
    CHECK(r2_apply_noise(payload, useful, 0.0, &rng, NULL, 0) == 0, "p=0 sin errores");
    CHECK(r2_apply_noise(payload, useful, 1.0, &rng, NULL, 0) == useful * 8u, "p=1 invierte todo");
    r2_apply_noise(payload, useful, 1.0, &rng, NULL, 0);          /* Restaura. */

    /* Ruido estadístico: 176 bits * 200 000 ensayos, p = 0.01 -> E = 1.76. */
    size_t flips = 0;
    const int trials = 200000;
    for (int i = 0; i < trials; i++) {
        flips += r2_apply_noise(payload, useful, 0.01, &rng, NULL, 0);
    }
    double mean = (double)flips / trials;
    CHECK(mean > 1.70 && mean < 1.82, "media de errores ~ n*p = 1.76");

    printf("\n%s\n", failures == 0 ? "Todas las pruebas pasaron." : "HAY PRUEBAS FALLIDAS.");
    return failures == 0 ? 0 : 1;
}
