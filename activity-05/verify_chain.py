#!/usr/bin/env python3
"""
Q10 — Certificate chain validation (PKI Activity)
Requires:
  pip install pyopenssl pem

Files expected in the working directory:
  - target.cert              (leaf certificate in PEM; e.g., twitter_com.cert)
  - intermediate.cert        (one or more intermediates concatenated in PEM; optional but recommended)
  - ca-certificates.crt      (root CA bundle in PEM)

Usage examples:
  python verify_chain.py --target twitter_com.cert --intermediate intermediate.cert --roots ca-certificates.crt
  python verify_chain.py --batch twitter_com.cert google.cert chula.cert classdeedee.cert --intermediate intermediate.cert --roots ca-certificates.crt
"""
import argparse
import sys
from OpenSSL import crypto
import pem
from typing import List, Optional

def load_pem_file(path: str) -> str:
    with open(path, 'r', encoding='utf-8') as f:
        return f.read()

def parse_pem_bundle(path: str) -> List[str]:
    """Return a list of PEM-encoded certs as strings from a bundle file (e.g., ca-certificates.crt)."""
    pems = pem.parse_file(path)
    return [str(p) for p in pems]

def verify_chain_of_trust(cert_pem: str, trusted_cert_pems: List[str]) -> Optional[str]:
    """
    Returns None if validation succeeds (PyOpenSSL semantics), otherwise returns a string error message.
    """
    try:
        certificate = crypto.load_certificate(crypto.FILETYPE_PEM, cert_pem)
    except Exception as e:
        return f"Failed to parse target certificate: {e}"

    store = crypto.X509Store()
    for trusted_cert_pem in trusted_cert_pems:
        try:
            trusted_cert = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_cert_pem)
            store.add_cert(trusted_cert)
        except Exception as e:
            return f"Failed to load a trusted certificate: {e}"

    try:
        store_ctx = crypto.X509StoreContext(store, certificate)
        result = store_ctx.verify_certificate()  # None on success
        return result  # None means OK
    except Exception as e:
        return str(e)

def main():
    parser = argparse.ArgumentParser(description="Verify an X.509 certificate chain of trust.")
    parser.add_argument("--target", help="PEM file for the leaf certificate to verify (e.g., twitter_com.cert).")
    parser.add_argument("--intermediate", help="PEM file containing intermediate cert(s). Optional but recommended.")
    parser.add_argument("--roots", default="ca-certificates.crt", help="Root CA bundle in PEM (default: ca-certificates.crt).")
    parser.add_argument("--batch", nargs="*", help="Verify multiple target certs. Provide file paths after --batch.")
    args = parser.parse_args()

    # Prepare trusted set: all roots (+ intermediates if provided)
    trusted: List[str] = []
    try:
        trusted.extend(parse_pem_bundle(args.roots))
    except Exception as e:
        print(f"[ERROR] Could not read root bundle '{args.roots}': {e}")
        sys.exit(2)

    if args.intermediate:
        try:
            # Allow multiple intermediates concatenated in one file
            trusted.extend(parse_pem_bundle(args.intermediate))
        except Exception:
            # Fallback: treat it as a single PEM (not a bundle parsed by pem)
            try:
                trusted.append(load_pem_file(args.intermediate))
            except Exception as e:
                print(f"[ERROR] Could not read intermediate cert(s) '{args.intermediate}': {e}")
                sys.exit(2)

    def verify_one(path: str) -> int:
        try:
            cert_pem = load_pem_file(path)
        except Exception as e:
            print(f"[{path}] ❌ Could not read: {e}")
            return 2

        err = verify_chain_of_trust(cert_pem, trusted)
        if err is None:
            print(f"[{path}] ✅ Certificate verified")
            return 0
        else:
            print(f"[{path}] ❌ Verification failed: {err}")
            # Common hint for 'unable to get local issuer certificate'
            if "unable to get local issuer" in err.lower() or "unable to get issuer" in err.lower():
                print("  Hint: Ensure all required intermediate certs are included via --intermediate.")
            return 1

    rc = 0
    if args.batch:
        for p in args.batch:
            rc |= verify_one(p)
    elif args.target:
        rc = verify_one(args.target)
    else:
        print("Provide --target <file> or use --batch <file1> <file2> ...")
        rc = 2
    sys.exit(rc)

if __name__ == "__main__":
    main()
