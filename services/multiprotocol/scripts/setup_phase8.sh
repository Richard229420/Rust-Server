#!/usr/bin/env bash
set -euo pipefail
umask 077
cd "$(dirname "$0")/.."
SECRETS_DIR="$HOME/.config/rust-server"
mkdir -p "$SECRETS_DIR" certs
chmod 700 "$SECRETS_DIR"
for secret in bus.token bus-read.token bus-write.token mqtt-bridge.token mqtt-lab.token; do
  if [[ ! -f "$SECRETS_DIR/$secret" ]]; then
    openssl rand -hex 32 > "$SECRETS_DIR/$secret"
  fi
  chmod 600 "$SECRETS_DIR/$secret"
done

# Nao usar CA:TRUE como certificado final do servidor. Criar CA local
# e assinar folha CA:FALSE com EKU serverAuth e SAN localhost / 127.0.0.1.
check_pair() {
  local cert="$1" key="$2" cp kp
  cp="$(openssl x509 -in "$cert" -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
  kp="$(openssl pkey -in "$key" -pubout -outform DER 2>/dev/null | openssl dgst -sha256)" || return 1
  [[ -n "$cp" && "$cp" == "$kp" ]]
}
check_certs() {
  [[ -s certs/ca.crt && -s certs/ca.key && -s certs/localhost.crt && -s certs/localhost.key ]] || return 1
  check_pair certs/ca.crt certs/ca.key || return 1
  check_pair certs/localhost.crt certs/localhost.key || return 1
  openssl verify -CAfile certs/ca.crt -purpose sslserver certs/localhost.crt >/dev/null 2>&1 || return 1
  openssl x509 -in certs/localhost.crt -noout -checkend 86400 >/dev/null 2>&1 || return 1
  openssl x509 -in certs/localhost.crt -noout -ext subjectAltName 2>/dev/null | rg -q 'DNS:localhost' || return 1
  openssl x509 -in certs/localhost.crt -noout -ext subjectAltName 2>/dev/null | rg -q 'IP Address:127\.0\.0\.1' || return 1
}

if check_certs; then
  echo '[TLS] Certificado servidor e CA existentes, validos. Preservados.'
else
  # Se houver CA parcial/corrompida, interromper em vez de perder a chave de confianca.
  if [[ -e certs/ca.crt || -e certs/ca.key ]]; then
    echo '[ERRO] CA local ja existente mas cadeia/chave invalida ou certificado servidor vencido.' >&2
    echo 'Inspecione certs/ca.crt, certs/ca.key e certs/localhost.*; nao sobrescritos.' >&2
    exit 1
  fi

  tmpdir="$(mktemp -d "${PWD}/certs/.fase8-tls.XXXXXXXX")"
  trap 'rm -rf "$tmpdir"' EXIT
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 365 \
    -keyout "$tmpdir/ca.key" -out "$tmpdir/ca.crt" \
    -subj '/CN=Rust Server Local Lab CA' \
    -addext 'basicConstraints=critical,CA:TRUE,pathlen:0' \
    -addext 'keyUsage=critical,keyCertSign,cRLSign' >/dev/null 2>&1
  openssl req -new -newkey rsa:3072 -nodes -sha256 \
    -keyout "$tmpdir/localhost.key" -out "$tmpdir/localhost.csr" \
    -subj '/CN=localhost' >/dev/null 2>&1
  cat > "$tmpdir/leaf.ext" <<'EOF'
basicConstraints=critical,CA:FALSE
keyUsage=critical,digitalSignature,keyEncipherment
extendedKeyUsage=serverAuth
subjectAltName=DNS:localhost,IP:127.0.0.1
subjectKeyIdentifier=hash
authorityKeyIdentifier=keyid,issuer
EOF
  openssl x509 -req -in "$tmpdir/localhost.csr" \
    -CA "$tmpdir/ca.crt" -CAkey "$tmpdir/ca.key" \
    -set_serial "0x$(openssl rand -hex 16)" -days 90 -sha256 \
    -extfile "$tmpdir/leaf.ext" -out "$tmpdir/localhost.crt" >/dev/null 2>&1
  openssl verify -CAfile "$tmpdir/ca.crt" -purpose sslserver "$tmpdir/localhost.crt" >/dev/null
  check_pair "$tmpdir/ca.crt" "$tmpdir/ca.key"
  check_pair "$tmpdir/localhost.crt" "$tmpdir/localhost.key"

  if [[ -e certs/localhost.crt || -e certs/localhost.key ]]; then
    backup="certs/backup-$(date +%Y%m%d-%H%M%S)-$$"
    mkdir -m 700 "$backup"
    for f in certs/localhost.crt certs/localhost.key; do
      if [[ -e "$f" ]]; then cp -p "$f" "$backup/"; fi
    done
    echo "[TLS] Certificado antigo copiado com seguranca para $backup"
  fi
  # Instalar depois de gerar e validar toda a cadeia, com modo restrito.
  install -m 600 "$tmpdir/ca.key" certs/ca.key
  install -m 644 "$tmpdir/ca.crt" certs/ca.crt
  install -m 600 "$tmpdir/localhost.key" certs/localhost.key
  install -m 644 "$tmpdir/localhost.crt" certs/localhost.crt
  echo '[TLS] Nova CA local e certificado leaf (CA:FALSE) instalados.'
fi

chmod 600 certs/ca.key certs/localhost.key
printf '%s\n' 'Credenciais locais preparadas em ~/.config/rust-server/' \
  'CA publica: certs/ca.crt' \
  'Certificado servidor: certs/localhost.crt (CA:FALSE)' \
  'As chaves *.key sao privadas. Nunca copie para clientes ou para Git.' \
  'Execute: source scripts/env_phase8.sh' \
  'Nao use esta CA privada/autogerida diretamente em producao.'
