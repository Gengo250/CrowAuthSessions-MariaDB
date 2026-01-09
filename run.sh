#!/usr/bin/env bash
set -euo pipefail

cd "$(dirname "$0")"

# Carrega variáveis do banco
source .env

echo "[+] Compilando..."
g++ -std=c++20 main.cpp todo.cpp -O2 -pthread $(pkg-config --cflags --libs libmariadb) -o app

echo "[+] Rodando em http://localhost:18080 ..."
./app
