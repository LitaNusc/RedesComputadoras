/**
 * @file    emisor.c
 * @brief   Emisor de tramas Ethernet (capa 2 OSI) con canal ruidoso simulado.
 *
 * Flujo:
 *   1. Arma el payload [LONGITUD | MENSAJE | CRC-32 | RELLENO].
 *   2. Por cada trama a enviar, copia el payload y aplica ruido (cada bit se
 *      invierte con probabilidad p) sobre la región útil.
 *   3. Antepone la cabecera Ethernet y la inyecta con pcap_sendpacket().
 *
 * Uso:  sudo ./emisor -i IFACE [-d MAC] [-m MENSAJE] [-p PROB] [-n N]
 *                     [-s SEMILLA] [-t MS] [-v]
 */
#include <arpa/inet.h>
#include <errno.h>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "r2_common.h"

#define DEFAULT_MESSAGE   "Hola Redes2027-1"
#define MAX_LOGGED_FLIPS  32u   /* Posiciones de bit que se imprimen por trama. */

/** Parámetros de línea de comandos. */
typedef struct {
    const char *iface;                  /**< Interfaz de salida (obligatoria). */
    const char *message;                /**< Texto a transmitir.               */
    uint8_t     dst_mac[R2_MAC_LEN];    /**< MAC destino (por defecto bcast).  */
    double      noise_p;                /**< Probabilidad de error por bit.    */
    long        count;                  /**< Número de tramas a enviar.        */
    long        interval_ms;            /**< Pausa entre tramas.               */
    uint64_t    seed;                   /**< Semilla del generador de ruido.   */
    int         verbose;                /**< Imprime las cadenas de bits.      */
} config_t;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s -i IFACE [opciones]\n"
        "  -i IFACE   Interfaz de red por la que se envía (obligatorio)\n"
        "  -d MAC     MAC destino, formato aa:bb:cc:dd:ee:ff (def.: broadcast)\n"
        "  -m TEXTO   Mensaje a enviar (def.: \"%s\")\n"
        "  -p PROB    Probabilidad de que un bit se invierta, 0..1 (def.: 0)\n"
        "  -n N       Número de tramas a enviar (def.: 1)\n"
        "  -s SEMILLA Semilla del generador de ruido (def.: basada en el reloj)\n"
        "  -t MS      Pausa entre tramas en milisegundos (def.: 1000)\n"
        "  -v         Muestra las cadenas de bits antes/después del ruido\n"
        "  -h         Muestra esta ayuda\n"
        "Requiere privilegios (root o CAP_NET_RAW).\n",
        prog, DEFAULT_MESSAGE);
}

/** Convierte @p text a double validando todo el texto. @return 0 si es válido. */
static int parse_double(const char *text, double *out)
{
    char *end = NULL;
    errno = 0;
    double v = strtod(text, &end);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

/** Convierte @p text a long validando todo el texto. @return 0 si es válido. */
static int parse_long(const char *text, long *out)
{
    char *end = NULL;
    errno = 0;
    long v = strtol(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0') {
        return -1;
    }
    *out = v;
    return 0;
}

/** Lee y valida los argumentos. @return 0 si todo es correcto. */
static int parse_args(int argc, char **argv, config_t *cfg)
{
    long seed_arg = -1;
    int opt;

    memset(cfg, 0, sizeof(*cfg));
    cfg->message     = DEFAULT_MESSAGE;
    cfg->count       = 1;
    cfg->interval_ms = 1000;
    memset(cfg->dst_mac, 0xFF, R2_MAC_LEN);           /* Broadcast por defecto. */

    while ((opt = getopt(argc, argv, "i:d:m:p:n:s:t:vh")) != -1) {
        switch (opt) {
        case 'i': cfg->iface   = optarg; break;
        case 'm': cfg->message = optarg; break;
        case 'v': cfg->verbose = 1;      break;
        case 'd':
            if (r2_parse_mac(optarg, cfg->dst_mac) != 0) {
                fprintf(stderr, "MAC destino inválida: %s\n", optarg);
                return -1;
            }
            break;
        case 'p':
            if (parse_double(optarg, &cfg->noise_p) != 0 ||
                cfg->noise_p < 0.0 || cfg->noise_p > 1.0) {
                fprintf(stderr, "La probabilidad debe estar en [0, 1]: %s\n", optarg);
                return -1;
            }
            break;
        case 'n':
            if (parse_long(optarg, &cfg->count) != 0 || cfg->count < 1) {
                fprintf(stderr, "N debe ser un entero >= 1: %s\n", optarg);
                return -1;
            }
            break;
        case 't':
            if (parse_long(optarg, &cfg->interval_ms) != 0 || cfg->interval_ms < 0) {
                fprintf(stderr, "MS debe ser un entero >= 0: %s\n", optarg);
                return -1;
            }
            break;
        case 's':
            if (parse_long(optarg, &seed_arg) != 0 || seed_arg < 0) {
                fprintf(stderr, "La semilla debe ser un entero >= 0: %s\n", optarg);
                return -1;
            }
            break;
        case 'h':
        default:
            return -1;
        }
    }

    if (cfg->iface == NULL) {
        fprintf(stderr, "Falta la interfaz (-i).\n");
        return -1;
    }
    if (strlen(cfg->message) == 0u || strlen(cfg->message) > R2_MAX_MSG_LEN) {
        fprintf(stderr, "El mensaje debe tener entre 1 y %u bytes.\n", R2_MAX_MSG_LEN);
        return -1;
    }

    cfg->seed = (seed_arg >= 0) ? (uint64_t)seed_arg
                                : (uint64_t)time(NULL) ^ ((uint64_t)getpid() << 32);
    return 0;
}

/** Pausa @p ms milisegundos. */
static void sleep_ms(long ms)
{
    struct timespec ts = { .tv_sec = ms / 1000, .tv_nsec = (ms % 1000) * 1000000L };
    nanosleep(&ts, NULL);
}

/** Imprime la cadena de bits de @p buf con una etiqueta. */
static void print_bits(const char *label, const uint8_t *buf, size_t len)
{
    char bits[R2_MAX_FRAME * 9u + 1u];
    r2_bits_to_string(buf, len, bits, sizeof(bits));
    printf("  %s (%zu bits):\n    %s\n", label, len * 8u, bits);
}

int main(int argc, char **argv)
{
    config_t cfg;
    if (parse_args(argc, argv, &cfg) != 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* --- 1. Datos de la trama --------------------------------------- */
    uint8_t src_mac[R2_MAC_LEN];
    if (r2_get_iface_mac(cfg.iface, src_mac) != 0) {
        fprintf(stderr, "No se pudo obtener la MAC de '%s' (¿existe la interfaz?)\n",
                cfg.iface);
        return EXIT_FAILURE;
    }

    uint8_t clean_payload[R2_MAX_PAYLOAD];
    size_t  useful_len = 0, payload_len = 0;
    if (r2_build_payload((const uint8_t *)cfg.message, strlen(cfg.message),
                         clean_payload, sizeof(clean_payload),
                         &useful_len, &payload_len) != 0) {
        fprintf(stderr, "No se pudo construir el payload.\n");
        return EXIT_FAILURE;
    }

    /* --- 2. Apertura del dispositivo -------------------------------- */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(cfg.iface, (int)R2_MAX_FRAME,
                                    0 /* sin modo promiscuo */, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s): %s\n(¿ejecutaste con sudo?)\n",
                cfg.iface, errbuf);
        return EXIT_FAILURE;
    }

    char src_txt[18], dst_txt[18];
    r2_format_mac(src_mac, src_txt);
    r2_format_mac(cfg.dst_mac, dst_txt);
    printf("=== EMISOR capa 2 ===\n"
           "Interfaz : %s\nMAC orig.: %s\nMAC dest.: %s\n"
           "EtherType: 0x%04X\nMensaje  : \"%s\" (%zu bytes)\n"
           "Payload  : %zu bytes (%zu útiles + %zu de relleno)\n"
           "Ruido p  : %g por bit | Semilla: %llu | Tramas: %ld\n\n",
           cfg.iface, src_txt, dst_txt, R2_ETHERTYPE, cfg.message,
           strlen(cfg.message), payload_len, useful_len, payload_len - useful_len,
           cfg.noise_p, (unsigned long long)cfg.seed, cfg.count);

    /* --- 3. Envío ---------------------------------------------------- */
    r2_rng_t rng;
    r2_rng_seed(&rng, cfg.seed);

    uint8_t frame[R2_MAX_FRAME];
    r2_eth_header_t hdr;
    memcpy(hdr.dst, cfg.dst_mac, R2_MAC_LEN);
    memcpy(hdr.src, src_mac, R2_MAC_LEN);
    hdr.ethertype = htons(R2_ETHERTYPE);              /* Orden de red.        */
    memcpy(frame, &hdr, sizeof(hdr));

    int status = EXIT_SUCCESS;
    for (long k = 1; k <= cfg.count; k++) {
        /* Cada trama parte del payload limpio y recibe ruido independiente. */
        uint8_t *payload = frame + R2_ETH_HDR_LEN;
        memcpy(payload, clean_payload, payload_len);

        size_t flipped_at[MAX_LOGGED_FLIPS];
        size_t flips = r2_apply_noise(payload, useful_len, cfg.noise_p, &rng,
                                      flipped_at, MAX_LOGGED_FLIPS);

        const size_t frame_len = R2_ETH_HDR_LEN + payload_len;
        printf("[Trama %ld/%ld] %zu bytes | bits invertidos: %zu",
               k, cfg.count, frame_len, flips);
        for (size_t i = 0; i < flips && i < MAX_LOGGED_FLIPS; i++) {
            printf("%s%zu", (i == 0) ? " (posiciones: " : ", ", flipped_at[i]);
            if (i + 1u == flips || i + 1u == MAX_LOGGED_FLIPS) {
                printf("%s)", (flips > MAX_LOGGED_FLIPS) ? ", ..." : "");
            }
        }
        printf("\n");

        if (cfg.verbose) {
            print_bits("Payload limpio", clean_payload, useful_len);
            print_bits("Payload enviado", payload, useful_len);
        }

        /* pcap_sendpacket: 0 = éxito, -1 = error. El FCS lo agrega el NIC. */
        if (pcap_sendpacket(handle, frame, (int)frame_len) != 0) {
            fprintf(stderr, "pcap_sendpacket: %s\n", pcap_geterr(handle));
            status = EXIT_FAILURE;
            break;
        }
        if (k < cfg.count) {
            sleep_ms(cfg.interval_ms);
        }
    }

    pcap_close(handle);
    printf("\nEnvío finalizado.\n");
    return status;
}
