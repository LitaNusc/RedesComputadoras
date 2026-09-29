# Redes de Computadoras - Práctica: Capa 2 (Enlace de Datos)

## Estructura
| Ruta | Descripción |
|------|-------------|
| `include/r2_common.h`, `src/r2_common.c` | CRC-32, ruido, cadenas de bits, MAC, payload |
| `src/emisor.c` | Emisor de tramas (`pcap_sendpacket`) |
| `src/receptor.c` | Receptor de tramas (`pcap_loop`) |
| `tests/test_common.c` | Pruebas unitarias (`make check`) |
| `Dockerfile`, `docker-compose.yml` | Ejecución en contenedores |
| `reporte/reporte.tex` | Reporte en LaTeX |

## Compilar (Fedora)
```bash
sudo dnf install -y gcc make libpcap-devel
make && make check
```

## Ejecutar (requiere root)
```bash
sudo ./build/receptor -i IFACE -v                       # lado izquierdo
sudo ./build/emisor   -i IFACE -m "Hola Redes2027-1" -p 0.01 -n 10 -v   # lado derecho
```
Opciones completas: `./build/emisor -h` y `./build/receptor -h`.
