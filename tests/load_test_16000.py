#!/usr/bin/env python3
"""Carga HTTP/1.1 sem dependencias: 16 clientes x 1000 requisicoes = 16000.
Cada requisicao usa sua propria conexao TCP, pois o servidor envia Connection: close.
Execute somente contra o servidor local do seu laboratorio.
"""
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import Counter
import socket
import statistics
import time

HOST = "127.0.0.1"
PORT = 8080
CLIENTS = 16
REQUESTS_PER_CLIENT = 1000
SOCKET_TIMEOUT = 8
REQUEST = b"GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"


def request_once():
    start = time.perf_counter()
    with socket.create_connection((HOST, PORT), timeout=SOCKET_TIMEOUT) as sock:
        sock.settimeout(SOCKET_TIMEOUT)
        sock.sendall(REQUEST)
        parts = []
        while True:
            data = sock.recv(4096)
            if not data:
                break
            parts.append(data)
    elapsed_ms = (time.perf_counter() - start) * 1000
    response = b"".join(parts)
    head, separator, body = response.partition(b"\r\n\r\n")
    if not separator:
        raise RuntimeError(f"Resposta HTTP sem separador (bytes={len(response)})")
    status_line = head.split(b"\r\n", 1)[0]
    chunks = status_line.split()
    if len(chunks) < 2 or not chunks[1].isdigit():
        raise RuntimeError(f"Status HTTP invalido: {status_line!r}")
    for line in head.split(b"\r\n")[1:]:
        if line.lower().startswith(b"content-length:"):
            content_length = int(line.split(b":", 1)[1].strip())
            if content_length != len(body):
                raise RuntimeError(f"Body truncado: {len(body)} != {content_length}")
            break
    return int(chunks[1]), elapsed_ms


def client_job(client_id):
    codes = Counter()
    latencies = []
    failures = []
    for i in range(REQUESTS_PER_CLIENT):
        try:
            code, latency = request_once()
            codes[code] += 1
            latencies.append(latency)
        except (OSError, ValueError, RuntimeError) as exc:
            failures.append(f"cliente {client_id}, req {i + 1}: {exc}")
    return client_id, codes, latencies, failures


def percentile(sorted_values, percent):
    index = max(0, min(len(sorted_values) - 1, int((len(sorted_values) - 1) * percent)))
    return sorted_values[index]


def main():
    total = CLIENTS * REQUESTS_PER_CLIENT
    print(f"Teste: {CLIENTS} clientes x {REQUESTS_PER_CLIENT} requisicoes = {total}")
    print(f"Destino: http://{HOST}:{PORT}/ (HTTP/1.1, Connection: close)")
    print("NOTA: cliente != worker; cada worker reutiliza sua thread para muitos pedidos.\n")
    all_codes = Counter()
    all_latencies = []
    all_failures = []
    t0 = time.perf_counter()
    with ThreadPoolExecutor(max_workers=CLIENTS) as executor:
        futures = [executor.submit(client_job, i + 1) for i in range(CLIENTS)]
        for future in as_completed(futures):
            client_id, codes, latencies, failures = future.result()
            all_codes.update(codes)
            all_latencies.extend(latencies)
            all_failures.extend(failures)
            print(f"Cliente {client_id:02d}: 200={codes[200]:4d}, outros={sum(codes.values())-codes[200]:4d}, erros={len(failures):3d}")
    duration = time.perf_counter() - t0
    success = all_codes[200]
    print("\n--- RESULTADOS ---")
    print(f"Requisicoes planejadas: {total}")
    print(f"HTTP 200: {success}")
    print(f"Codigos HTTP: {dict(sorted(all_codes.items()))}")
    print(f"Falhas de rede/protocolo: {len(all_failures)}")
    print(f"Duracao total: {duration:.3f} s")
    print(f"Taxa: {total / duration:.1f} tentativas/s")
    print(f"Taxa HTTP 200: {success / duration:.1f} respostas/s")
    if all_latencies:
        ordered = sorted(all_latencies)
        print(f"Latencia mediana: {statistics.median(ordered):.3f} ms")
        print(f"Latencia p95: {percentile(ordered, 0.95):.3f} ms")
        print(f"Latencia p99: {percentile(ordered, 0.99):.3f} ms")
    if all_failures:
        print("\nExemplos de falha (ate 10):")
        for example in all_failures[:10]:
            print("  ", example)
    passed = success == total and not all_failures
    print(f"\nRESULTADO: {'APROVADO' if passed else 'NAO APROVADO'}")
    raise SystemExit(0 if passed else 1)


if __name__ == "__main__":
    main()
