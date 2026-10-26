storage "file" {
  path = "/vault/file"
}

# TLS on the listener: unseal keys, root and AppRole tokens and every secret
# cross the network between Vault and its clients. The certificate comes from
# scripts/gen-vault-tls.sh (vault/tls/, mounted read-only).
listener "tcp" {
  address         = "0.0.0.0:8200"
  tls_cert_file   = "/vault/tls/vault.pem"
  tls_key_file    = "/vault/tls/vault.key"
  tls_min_version = "tls12"
}

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"
ui           = true
disable_mlock = false
