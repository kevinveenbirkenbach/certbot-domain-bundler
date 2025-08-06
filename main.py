#!/usr/bin/env python3
import argparse
import subprocess
import sys
import hashlib
from collections import defaultdict

def chunk_list(lst, size):
    """Yield successive chunks of the given list."""
    for i in range(0, len(lst), size):
        yield lst[i:i + size]

def group_domains(domains, domain_categories):
    """Group domains either by specific categories or by their base domain (SLD.TLD)."""
    grouped = defaultdict(list)
    if domain_categories:
        # Sort categories descending by length to match the most specific first
        sorted_categories = sorted(domain_categories, key=lambda x: len(x), reverse=True)
        for domain in domains:
            matched = False
            for category in sorted_categories:
                if domain.endswith(category):
                    grouped[category].append(domain)
                    matched = True
                    break
            if not matched:
                parts = domain.split('.')
                if len(parts) >= 2:
                    key = '.'.join(parts[-2:])
                    grouped[key].append(domain)
    else:
        for domain in domains:
            parts = domain.split('.')
            if len(parts) >= 2:
                key = '.'.join(parts[-2:])
                grouped[key].append(domain)
    return grouped

def generate_domain_hash(all_domains):
    """Generate a short hash (first 8 characters) from all domains sorted alphabetically."""
    domains_sorted = sorted(all_domains)
    joined = ",".join(domains_sorted)
    hash_object = hashlib.sha256(joined.encode())
    return hash_object.hexdigest()[:8]

def request_cert(domains, cert_name, certbot_acme_challenge_method, certbot_credentials_file,
                 certbot_dns_propagation_seconds, certbot_email, letsencrypt_webroot_path,
                 mode_test=False):
    """Build and execute the Certbot command for the given domains and options."""
    base_command = [
        'certbot', 'certonly',
        '--agree-tos',
        '--non-interactive',
        '--expand',
        '--email', certbot_email,
        '--cert-name', cert_name
    ]

    if certbot_acme_challenge_method != 'webroot':
        base_command += [
            f'--dns-{certbot_acme_challenge_method}',
            f'--dns-{certbot_acme_challenge_method}-credentials', certbot_credentials_file,
            f'--dns-{certbot_acme_challenge_method}-propagation-seconds', str(certbot_dns_propagation_seconds)
        ]
    else:
        base_command += ['--webroot', '-w', letsencrypt_webroot_path]

    if mode_test:
        base_command.append('--test-cert')

    for domain in domains:
        base_command += ['-d', domain]

    print(f"[INFO] Running command for cert-name '{cert_name}': {' '.join(base_command)}")
    result = subprocess.run(base_command)

    if result.returncode != 0:
        print(f"[ERROR] Certbot failed for cert-name '{cert_name}'", file=sys.stderr)
        sys.exit(result.returncode)

def main():
    """Parse arguments and request certificates in batches if necessary."""
    parser = argparse.ArgumentParser(description='Request SAN certificates using Certbot.')
    parser.add_argument('--domains', type=str, required=True,
                        help='Comma-separated list of domains.')
    parser.add_argument('--domain-categories', type=str, default='',
                        help='Comma-separated list of domain categories for grouping.')
    parser.add_argument('--certbot-credentials-file', type=str, default=None,
                        help='Path to Certbot DNS credentials file (for DNS methods).')
    parser.add_argument('--certbot-acme-challenge-method', type=str, default='webroot',
                        help='ACME challenge method (default: webroot).')
    parser.add_argument('--certbot-dns-propagation-seconds', type=int, default=60,
                        help='Seconds to wait for DNS propagation (default: 60).')
    parser.add_argument('--certbot-email', type=str, required=True,
                        help='Email address for Certbot registration and recovery.')
    parser.add_argument('--letsencrypt-webroot-path', type=str, default='/var/lib/letsencrypt/',
                        help='Webroot path for webroot challenge (default: /var/lib/letsencrypt/).')
    parser.add_argument('--mode-test', action='store_true',
                        help='Use the Certbot staging environment for testing.')
    parser.add_argument('--chunk-size', type=int, default=0,
                        help='Maximum number of domains per certificate (0 = no chunking).')

    args = parser.parse_args()

    all_domains = [d.strip() for d in args.domains.split(',') if d.strip()]
    domain_hash = generate_domain_hash(all_domains)
    categories = [c.strip() for c in args.domain_categories.split(',') if c.strip()]
    grouped = group_domains(all_domains, categories)
    chunk_size = args.chunk_size

    # globaler Chunk-Zähler
    chunk_counter = 1
    for group_key, domain_list in grouped.items():
        batches = [domain_list]
        if chunk_size and len(domain_list) > chunk_size:
            batches = list(chunk_list(domain_list, chunk_size))

        for batch in batches:
            batch_suffix = str(chunk_counter).zfill(5)
            cert_name = f"certbundle-{domain_hash}-{batch_suffix}"
            print(f"[INFO] Requesting certificate for group '{group_key}' batch {chunk_counter}: {batch}")
            request_cert(
                domains=batch,
                cert_name=cert_name,
                certbot_acme_challenge_method=args.certbot_acme_challenge_method,
                certbot_credentials_file=args.certbot_credentials_file,
                certbot_dns_propagation_seconds=args.certbot_dns_propagation_seconds,
                certbot_email=args.certbot_email,
                letsencrypt_webroot_path=args.letsencrypt_webroot_path,
                mode_test=args.mode_test
            )
            chunk_counter += 1

if __name__ == '__main__':
    main()
