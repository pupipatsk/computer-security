#!/usr/bin/env bash
# get_site_certs.sh
# Save leaf and intermediate certs for a list of hosts.
# Output per host:
#   <host-with-dashes>.cert
#   <host-with-dashes>-intermediate.pem

set -euo pipefail

HOSTS=(
  "twitter.com"
  "google.com"
  "www.chula.ac.th"
  "classdeedee.cloud.cp.eng.chula.ac.th"
)

sanitize() {
  # replace anything not [A-Za-z0-9-] with '-', collapse repeats, trim ends
  echo "$1" | sed -e 's/[^A-Za-z0-9-]/-/g' -e 's/-\{2,\}/-/g' -e 's/^-//' -e 's/-$//'
}

save_leaf_and_chain() {
  local host="$1" chainfile="$2"
  # Capture *all* certificates sent by the server
  openssl s_client -connect "${host}:443" -servername "${host}" -showcerts </dev/null 2>/dev/null \
    | awk '/BEGIN CERTIFICATE/,/END CERTIFICATE/{print}' > "${chainfile}"
}

extract_leaf() {
  local chainfile="$1" leaf_out="$2"
  # First PEM block = leaf
  awk 'BEGIN{f=0} /BEGIN CERTIFICATE/{c++} c==1 {print} /END CERTIFICATE/ && c==1 {exit}' \
    "${chainfile}" > "${leaf_out}"
}

extract_intermediates_from_chain() {
  local chainfile="$1" inter_out="$2"
  : > "${inter_out}"
  # All PEM blocks after the first = intermediates
  awk '
    /BEGIN CERTIFICATE/ {i++}
    i>=2 {print}
  ' "${chainfile}" >> "${inter_out}"
}

fetch_intermediates_via_aia_if_needed() {
  local host="$1" leaf="$2" inter_out="$3"
  # If we already have some intermediates from handshake, keep them; only add via AIA if empty
  if grep -q "BEGIN CERTIFICATE" "${inter_out}" 2>/dev/null; then
    return 0
  fi

  echo "==> [${host}] no intermediates in handshake; trying AIA"
  # Pull CA Issuers URLs from the leaf; strip the leading "URI:" token if present
  while IFS= read -r url; do
    url="${url#URI:}"
    [ -n "$url" ] || continue
    tmp="$(mktemp)"
    if curl -fsSL "${url}" -o "${tmp}"; then
      # If DER, convert to PEM; else append as-is
      if openssl x509 -inform der -in "${tmp}" -outform pem >> "${inter_out}" 2>/dev/null; then
        :
      else
        cat "${tmp}" >> "${inter_out}"
      fi
    fi
    rm -f "${tmp}"
  done < <(
    openssl x509 -in "${leaf}" -noout -text \
    | awk '
        /Authority Information Access/ {inAIA=1; next}
        inAIA && /CA Issuers - URI:/ {print $NF; next}
        inAIA && /^ *X509v3/ {inAIA=0}
      '
  )
}

main() {
  command -v openssl >/dev/null || { echo "OpenSSL not found"; exit 1; }
  command -v curl    >/dev/null || { echo "curl not found"; exit 1; }

  for h in "${HOSTS[@]}"; do
    base="$(sanitize "${h}")"                 # e.g., google.com -> google-com
    chain="${base}-chain.pem"
    leaf="${base}.cert"                       # e.g., google-com.cert
    inter="${base}-intermediate.pem"          # e.g., google-com-intermediate.pem

    echo "==> [${h}] grabbing chain"
    save_leaf_and_chain "${h}" "${chain}"

    echo "==> [${h}] saving leaf -> ${leaf}"
    extract_leaf "${chain}" "${leaf}"
    if ! grep -q "BEGIN CERTIFICATE" "${leaf}"; then
      echo "!! [${h}] failed to save leaf cert"; rm -f "${chain}"; continue
    fi

    echo "==> [${h}] saving intermediates -> ${inter}"
    : > "${inter}"
    extract_intermediates_from_chain "${chain}" "${inter}"
    fetch_intermediates_via_aia_if_needed "${h}" "${leaf}" "${inter}"

    # Optional: quick subjects preview (comment out if you want *only* files)
    echo "    leaf:       $(openssl x509 -in "${leaf}" -noout -subject | sed 's/subject= //')"
    if grep -q "BEGIN CERTIFICATE" "${inter}"; then
      echo "    intermediates:"
      openssl crl2pkcs7 -nocrl -certfile "${inter}" | openssl pkcs7 -print_certs -noout | grep '^subject=' | sed 's/subject= /      - /'
    else
      echo "    intermediates: (none found)"
    fi

    # Keep the chain file for debugging; delete if you don't want it:
    # rm -f "${chain}"
    echo
  done
}

main "$@"
