# ---------------------------------------------------------------------------
# Practica Redes - Capa 2. Imagen basada en Fedora (mismo SO que el laboratorio).
# Construccion en dos etapas: la imagen final no incluye compilador.
# ---------------------------------------------------------------------------

# ---- Etapa 1: compilacion -------------------------------------------------
FROM fedora:latest AS build
RUN dnf install -y --setopt=install_weak_deps=False gcc make libpcap-devel \
    && dnf clean all
WORKDIR /src
COPY Makefile ./
COPY include/ include/
COPY src/ src/
RUN make

# ---- Etapa 2: ejecucion ---------------------------------------------------
FROM fedora:latest
# libpcap: biblioteca de captura | tcpdump / iproute: herramientas de diagnostico
RUN dnf install -y --setopt=install_weak_deps=False libpcap tcpdump iproute \
    && dnf clean all
COPY --from=build /src/build/emisor   /usr/local/bin/emisor
COPY --from=build /src/build/receptor /usr/local/bin/receptor
# Sin ENTRYPOINT: el comando se define en docker-compose.yml o con `docker run`.
CMD ["receptor", "-h"]
