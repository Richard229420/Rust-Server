#!/usr/bin/env python3
"""Fase 8.4.4: conserta somente a extensao keyUsage da CA do LAB 8884.

Diagnostico read-only: `diagnosticar`.
Correcao opt-in: `corrigir` (CA publica reemitida com MESMA chave).
Nao muda dinamico, senhas, chaves privadas, cert de servidor nem broker 8883.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile

import fase8_4_2_lab as lab
import fase8_4_4_online as online

ROOT = lab.ROOT
CA_NAME = 'ca.crt'
BACKUP_NAME = 'ca.crt.pre-8-4-4-strict.backup'
CA_SUBJECT = '/CN=Rust-Server MQTT Lab CA 8.4.2'


class Fail(Exception):
    pass


def require(ok, message):
    if not ok:
        raise Fail(message)


def cmd(args, *, ok=True):
    p = subprocess.run(args, capture_output=True, text=True, timeout=15, check=False)
    if ok:
        require(p.returncode == 0, 'Comando OpenSSL falhou; nenhum certificado foi substituido')
    return p


def sha(blob):
    return hashlib.sha256(blob).hexdigest()


def verify(cert_path, ca_path, strict):
    command = ['openssl', 'verify']
    if strict:
        command += ['-x509_strict']
    command += ['-CAfile', str(ca_path), '-verify_hostname', 'localhost', str(cert_path)]
    return cmd(command, ok=False).returncode == 0


def certificate_pubkey(cert):
    return cmd(['openssl', 'x509', '-in', str(cert), '-pubkey', '-noout']).stdout


def key_pubkey(key):
    return cmd(['openssl', 'pkey', '-in', str(key), '-pubout']).stdout


def cert_subject(path):
    return cmd(['openssl', 'x509', '-in', str(path), '-noout', '-subject', '-nameopt', 'RFC2253']).stdout.strip().removeprefix('subject=')


def cert_issuer(path):
    return cmd(['openssl', 'x509', '-in', str(path), '-noout', '-issuer', '-nameopt', 'RFC2253']).stdout.strip().removeprefix('issuer=')


def inspect_paths():
    require(os.geteuid() != 0, 'Nao execute com root/sudo')
    lab.validated_root()
    require(lab.port_open(8884), 'Broker de LAB 8884 precisa estar ativo')
    pki = ROOT / 'pki'
    ca, key, server = (pki / 'ca.crt', pki / 'ca.key', pki / 'server.crt')
    for path in (ca, key, server):
        lab.check_private(path)
    require('plugin_use labdynsec' in (ROOT / 'mosquitto-lab.conf').read_text(), 'Plugin nao configurado')
    require(certificate_pubkey(ca) == key_pubkey(key), 'Chave privada nao corresponde a CA; nao modificar')
    require(cert_subject(ca) == cert_issuer(server), 'CA e certificado do broker divergentes')
    require(verify(server, ca, strict=False), 'Certificado atual nao confere nem na verificacao OpenSSL comum')
    return ca, key, server


def tls_probe():
    context = ssl.create_default_context(cafile=str(ROOT / 'pki' / CA_NAME))
    require(context.verify_mode == ssl.CERT_REQUIRED and context.check_hostname, 'TLS nao seguro')
    with socket.create_connection(('127.0.0.1', 8884), timeout=4) as raw:
        with context.wrap_socket(raw, server_hostname='localhost'):
            pass


def diagnose():
    ca, key, server = inspect_paths()
    strict = verify(server, ca, strict=True)
    print('CA e certificado do servidor: assinatura e hostname aprovados na verificacao comum.')
    print('OpenSSL X509 estrito:', 'APROVADO' if strict else 'REPROVADO (CA legada: verificar extensoes X509)')
    try:
        tls_probe()
        print('Python TLS 8884: APROVADO (certificado e hostname validados).')
    except (OSError, ssl.SSLError):
        print('Python TLS 8884: REPROVADO (handshake ou verificacao de certificado).')
    print('Marcador 8.4.4:', online.read_state() or 'ausente')
    return strict


def repair():
    ca, key, server = inspect_paths()
    require(online.read_state() is None, 'Apply ja criou um marcador: nao corrigir/repetir sem auditoria do estado')
    require(not (ROOT / 'backup-fase8-4-4').exists(), 'Snapshot 8.4.4 existente: investigar antes da correcao')
    if verify(server, ca, strict=True):
        tls_probe()
        print('APROVADO: CA ja compativel com X509 estrito. Nada alterado.')
        return
    original = ca.read_bytes()
    backup = ROOT / 'pki' / BACKUP_NAME
    require(not backup.exists() and not backup.is_symlink(), 'Backup CA ja existe: nao sobrescrever')
    with tempfile.TemporaryDirectory(prefix='.ca-strict-', dir=ROOT / 'pki') as tmp:
        workspace = Path(tmp)
        config = workspace / 'ca.cnf'
        config.write_text('''[ req ]
prompt = no
distinguished_name = dn
x509_extensions = v3_ca
[ dn ]
CN = Rust-Server MQTT Lab CA 8.4.2
[ v3_ca ]
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
''', encoding='ascii')
        cert_new = workspace / 'ca-new.crt'
        cmd(['openssl', 'req', '-new', '-x509', '-sha256', '-days', '30',
             '-key', str(key), '-out', str(cert_new), '-config', str(config)])
        require(certificate_pubkey(cert_new) == certificate_pubkey(ca), 'Chave publica de CA mudou')
        require(cert_subject(cert_new) == cert_subject(ca), 'Subject de CA mudou')
        require(verify(server, cert_new, strict=True), 'Novo certificado nao valida o servidor de forma estrita')
        # IP SAN tambem deve continuar valido.
        require(cmd(['openssl', 'verify', '-x509_strict', '-CAfile', str(cert_new),
                     '-verify_ip', '127.0.0.1', str(server)], ok=False).returncode == 0,
                'Certificado nao valida IP 127.0.0.1')
        require(ca.read_bytes() == original, 'CA original mudou durante o procedimento')
        # Backup privado escrito com O_EXCL; nunca apagar automaticamente.
        fd = os.open(backup, os.O_CREAT | os.O_EXCL | os.O_WRONLY | os.O_NOFOLLOW, 0o600)
        with os.fdopen(fd, 'wb') as f:
            f.write(original)
            f.flush()
            os.fsync(f.fileno())
        lab.check_private(backup)
        os.chmod(cert_new, 0o600)
        os.replace(cert_new, ca)
    lab.check_private(ca)
    require(verify(server, ca, strict=True), 'Nova CA falhou apos substituicao; interrompa')
    tls_probe()
    print('APROVADO: CA publica reemitida com a MESMA chave; X509 estrito e handshake TLS aprovados.')
    print('APROVADO: certificado e chave do servidor, DynSec, credenciais e broker 8883 intactos.')
    print('Backup privado da antiga CA:', backup)
    print('O broker 8884 nao foi reiniciado. Execute preflight antes de apply.')


def main():
    os.umask(0o077)
    arg = argparse.ArgumentParser(description=__doc__)
    arg.add_argument('action', choices=['diagnosticar', 'corrigir'])
    args = arg.parse_args()
    try:
        if args.action == 'diagnosticar':
            diagnose()
        else:
            repair()
    except (Fail, lab.Abort, online.Failure, OSError, ssl.SSLError, subprocess.TimeoutExpired) as exc:
        # Mensagem controlada; jamais imprimir senha ou dados do certificado privado.
        if isinstance(exc, (Fail, lab.Abort, online.Failure)):
            print('REPROVADO:', exc, file=sys.stderr)
        else:
            print('INCONCLUSIVO: falha OpenSSL/TLS ou no estado privado, nao executar apply.', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
