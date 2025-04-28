import argparse
import subprocess
from collections import defaultdict


def group_domains(domains, categorize_by_domain):
    grouped = defaultdict(list)
    for domain in domains:
        if domain.endswith(categorize_by_domain):
            grouped[categorize_by_domain].append(domain)
        else:
            parts = domain.split('.')
            if len(parts) >= 2:
                key = '.'.join(parts[-2:])
                grouped[key].append(domain)
    return grouped


def request_cert(domains, certbot_acme_challenge_method, certbot_credentials_file, certbot_dns_propagation_seconds, certbot_email, certbot_webroot_path, mode_test=False):
    base_command = [
        'certbot', 'certonly',
        '--agree-tos',
        '--non-interactive',
        '--email', certbot_email
    ]

    if certbot_acme_challenge_method != 'webroot':
        base_command += [
            f'--dns-{certbot_acme_challenge_method}',
            f'--dns-{certbot_acme_challenge_method}-credentials', certbot_credentials_file,
            f'--dns-{certbot_acme_challenge_method}-propagation-seconds', str(certbot_dns_propagation_seconds)
        ]
    else:
        base_command += ['--webroot', '-w', certbot_webroot_path]

    if mode_test:
        base_command.append('--test-cert')

    for domain in domains:
        base_command += ['-d', domain]

    print("[INFO] Running command:", ' '.join(base_command))
    subprocess.run(base_command, check=True)


def main():
    parser = argparse.ArgumentParser(description='Request SAN certificates with Certbot.')
    parser.add_argument('--domains', type=str, required=True,
                        help='Comma-separated list of all domains.')
    parser.add_argument('--categorize-by-domain', type=str, required=True,
                        help='Domain under which to group subdomains.')
    parser.add_argument('--certbot-credentials-file', type=str, default=None,
                        help='Path to the Certbot DNS credentials file (only for DNS challenge methods).')
    parser.add_argument('--certbot-acme-challenge-method', type=str, default='webroot',
                        help='ACME challenge method (default: webroot).')
    parser.add_argument('--certbot-dns-propagation-seconds', type=int, default=60,
                        help='Seconds to wait for DNS propagation (default: 60).')
    parser.add_argument('--certbot-email', type=str, required=True,
                        help='Email address for Certbot registration and recovery.')
    parser.add_argument('--certbot-webroot-path', type=str, default='/var/lib/letsencrypt/',
                        help='Webroot path to use for webroot challenge method (default: /var/lib/letsencrypt/).')
    parser.add_argument('--mode-test', action='store_true',
                        help='Use the Certbot test environment.')

    args = parser.parse_args()

    domains = [d.strip() for d in args.domains.split(',') if d.strip()]

    grouped_domains = group_domains(domains, args.categorize_by_domain)

    for group_key, domain_list in grouped_domains.items():
        print(f"[INFO] Requesting certificate for group '{group_key}' with domains: {domain_list}")
        request_cert(
            domains=domain_list,
            certbot_acme_challenge_method=args.certbot_acme_challenge_method,
            certbot_credentials_file=args.certbot_credentials_file,
            certbot_dns_propagation_seconds=args.certbot_dns_propagation_seconds,
            certbot_email=args.certbot_email,
            certbot_webroot_path=args.certbot_webroot_path,
            mode_test=args.mode_test
        )


if __name__ == '__main__':
    main()
