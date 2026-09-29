# ---------------------------------------------------------------------------
# Makefile - Practica Redes de Computadoras: Capa 2 (Fedora / gcc / libpcap)
#
# Objetivos:
#   make          Compila emisor y receptor en build/
#   make check    Ejecuta las pruebas unitarias (no requiere privilegios)
#   make clean    Elimina build/
#
# Dependencias en Fedora:  sudo dnf install gcc make libpcap-devel
# ---------------------------------------------------------------------------
CC      ?= gcc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_DEFAULT_SOURCE -Wall -Wextra -Wpedantic -Iinclude
LDLIBS  := -lpcap

BUILD   := build
COMMON  := $(BUILD)/r2_common.o

.PHONY: all check clean

all: $(BUILD)/emisor $(BUILD)/receptor

$(BUILD):
	mkdir -p $@

# Regla generica: src/X.c -> build/X.o (se recompila si cambia el header).
$(BUILD)/%.o: src/%.c include/r2_common.h | $(BUILD)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD)/emisor: $(BUILD)/emisor.o $(COMMON)
	$(CC) $^ -o $@ $(LDLIBS)

$(BUILD)/receptor: $(BUILD)/receptor.o $(COMMON)
	$(CC) $^ -o $@ $(LDLIBS)

$(BUILD)/test_common: tests/test_common.c $(COMMON) | $(BUILD)
	$(CC) $(CFLAGS) $^ -o $@

check: $(BUILD)/test_common
	./$(BUILD)/test_common

clean:
	rm -rf $(BUILD)
