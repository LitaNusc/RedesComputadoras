/**
 * @file    receptor.c
 * @brief   Receptor de tramas Ethernet (capa 2 OSI) con verificación de errores.
 *
 * Captura con libpcap únicamente las tramas con EtherType 0x88B5 (filtro BPF),
 * extrae el payload, recalcula el CRC-32 y reporta si el canal ruidoso
 * corrompió la trama. Al terminar (Ctrl+C o al alcanzar -c) imprime
 * estadísticas de tramas correctas y corruptas.
 *
 * Uso:  sudo ./receptor -i IFACE [-c N] [-v]
 */
#include <arpa/inet.h>
#include <ctype.h>
#include <pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

#include "r2_common.h"

/** Contadores acumulados durante la captura. */
typedef struct {
    unsigned long total;      /**< Tramas 0x88B5 recibidas.            */
    unsigned long ok;         /**< Tramas cuyo CRC coincidió.          */
    unsigned long corrupt;    /**< Tramas con ruido detectado.         */
    int           verbose;    /**< Imprime cadenas de bits.            */
} rx_stats_t;

/** Manejador global para que la señal pueda interrumpir pcap_loop(). */
static pcap_t *g_handle = NULL;

static void usage(const char *prog)
{
    fprintf(stderr,
        "Uso: %s -i IFACE [-c N] [-v]\n"
        "  -i IFACE  Interfaz de red donde se escucha (obligatorio)\n"
        "  -c N      Termina tras N tramas (def.: 0 = hasta Ctrl+C)\n"
        "  -v        Muestra la cadena de bits del payload recibido\n"
        "  -h        Muestra esta ayuda\n"
        "Requiere privilegios (root o CAP_NET_RAW).\n", prog);
}

/** Ctrl+C / SIGTERM: solicita salir del bucle de captura de forma limpia. */
static void on_signal(int sig)
{
    (void)sig;
    if (g_handle != NULL) {
        pcap_breakloop(g_handle);     /* Es seguro llamarla desde un handler. */
    }
}

/** Copia @p src a @p dst reemplazando los bytes no imprimibles por '.'. */
static void sanitize(const uint8_t *src, size_t len, char *dst)
{
    for (size_t i = 0; i < len; i++) {
        dst[i] = isprint(src[i]) ? (char)src[i] : '.';
    }
    dst[len] = '\0';
}

/**
 * Callback invocado por pcap_loop() por cada trama capturada.
 *
 * @param user   Puntero a rx_stats_t (pasado como u_char* por la API).
 * @param hdr    Metadatos de captura (marca de tiempo, caplen, len).
 * @param bytes  Trama completa desde la cabecera Ethernet.
 */
static void on_frame(u_char *user, const struct pcap_pkthdr *hdr,
                     const u_char *bytes)
{
    rx_stats_t *stats = (rx_stats_t *)user;

    if (hdr->caplen < R2_ETH_HDR_LEN) {
        return;                                       /* Trama incompleta.    */
    }

    r2_eth_header_t eth;
    memcpy(&eth, bytes, sizeof(eth));                 /* Evita accesos desalineados. */
    if (ntohs(eth.ethertype) != R2_ETHERTYPE) {
        return;                                       /* Defensa extra al BPF. */
    }

    const uint8_t *payload = bytes + R2_ETH_HDR_LEN;
    const size_t   payload_len = hdr->caplen - R2_ETH_HDR_LEN;

    size_t   msg_len = 0;
    uint32_t crc_rx = 0, crc_calc = 0;
    const r2_parse_status_t st =
        r2_parse_payload(payload, payload_len, &msg_len, &crc_rx, &crc_calc);

    stats->total++;

    char src_txt[18], dst_txt[18], when[16];
    r2_format_mac(eth.src, src_txt);
    r2_format_mac(eth.dst, dst_txt);
    time_t sec = hdr->ts.tv_sec;
    struct tm tm_local;
    localtime_r(&sec, &tm_local);
    strftime(when, sizeof(when), "%H:%M:%S", &tm_local);

    printf("[%s.%06ld] Trama #%lu | %s -> %s | %u bytes\n", when,
           (long)hdr->ts.tv_usec, stats->total, src_txt, dst_txt, hdr->caplen);

    switch (st) {
    case R2_PARSE_OK: {
        char text[R2_MAX_MSG_LEN + 1u];
        sanitize(payload + R2_LEN_FIELD, msg_len, text);
        stats->ok++;
        printf("  Estado : OK (CRC-32 0x%08X coincide)\n  Mensaje: \"%s\"\n",
               crc_rx, text);
        break;
    }
    case R2_PARSE_BAD_CRC: {
        char text[R2_MAX_MSG_LEN + 1u];
        sanitize(payload + R2_LEN_FIELD, msg_len, text);
        stats->corrupt++;
        printf("  Estado : CORRUPTA (CRC recibido 0x%08X != calculado 0x%08X)\n"
               "  Mensaje: \"%s\"  <- contenido NO confiable\n",
               crc_rx, crc_calc, text);
        break;
    }
    case R2_PARSE_BAD_LENGTH:
        stats->corrupt++;
        printf("  Estado : CORRUPTA (el campo LONGITUD es incoherente)\n");
        break;
    case R2_PARSE_TOO_SHORT:
    default:
        stats->corrupt++;
        printf("  Estado : CORRUPTA (payload demasiado corto)\n");
        break;
    }

    if (stats->verbose) {
        char bits[R2_MAX_FRAME * 9u + 1u];
        r2_bits_to_string(payload, payload_len, bits, sizeof(bits));
        printf("  Bits   : %s\n", bits);
    }
    printf("\n");
    fflush(stdout);
}

int main(int argc, char **argv)
{
    const char *iface = NULL;
    long        max_frames = 0;
    rx_stats_t  stats = {0, 0, 0, 0};
    int         opt;

    while ((opt = getopt(argc, argv, "i:c:vh")) != -1) {
        switch (opt) {
        case 'i': iface = optarg;          break;
        case 'c': max_frames = atol(optarg); break;
        case 'v': stats.verbose = 1;       break;
        case 'h':
        default:  usage(argv[0]);          return EXIT_FAILURE;
        }
    }
    if (iface == NULL || max_frames < 0) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }

    /* --- Apertura: snaplen cubre una trama completa; modo promiscuo ---- */
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = pcap_open_live(iface, (int)R2_MAX_FRAME, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live(%s): %s\n(¿ejecutaste con sudo?)\n",
                iface, errbuf);
        return EXIT_FAILURE;
    }
    g_handle = handle;

    /* Ignora las tramas que este mismo host emite por la interfaz. */
    if (pcap_setdirection(handle, PCAP_D_IN) != 0) {
        fprintf(stderr, "Aviso: pcap_setdirection: %s\n", pcap_geterr(handle));
    }

    /* Filtro BPF: el kernel descarta todo lo que no sea EtherType 0x88B5. */
    struct bpf_program prog;
    if (pcap_compile(handle, &prog, R2_BPF_FILTER, 1, PCAP_NETMASK_UNKNOWN) != 0 ||
        pcap_setfilter(handle, &prog) != 0) {
        fprintf(stderr, "Filtro BPF: %s\n", pcap_geterr(handle));
        pcap_close(handle);
        return EXIT_FAILURE;
    }
    pcap_freecode(&prog);

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = on_signal;
    sigemptyset(&sa.sa_mask);
    sigaction(SIGINT,  &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);

    printf("=== RECEPTOR capa 2 ===\nInterfaz : %s\nFiltro   : %s\n"
           "Esperando tramas... (Ctrl+C para terminar)\n\n", iface, R2_BPF_FILTER);
    fflush(stdout);

    /* --- Bucle de captura: bloquea hasta N tramas o pcap_breakloop() --- */
    int rc = pcap_loop(handle, (int)max_frames, on_frame, (u_char *)&stats);
    int status = EXIT_SUCCESS;
    if (rc == PCAP_ERROR) {
        fprintf(stderr, "pcap_loop: %s\n", pcap_geterr(handle));
        status = EXIT_FAILURE;
    }

    pcap_close(handle);
    g_handle = NULL;

    printf("=== Resumen ===\nRecibidas: %lu | Correctas: %lu | Corruptas: %lu",
           stats.total, stats.ok, stats.corrupt);
    if (stats.total > 0) {
        printf(" (%.2f %% corruptas)", 100.0 * (double)stats.corrupt / (double)stats.total);
    }
    printf("\n");
    return status;
}
