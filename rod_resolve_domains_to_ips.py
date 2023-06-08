import dns.resolver
import argparse
from collections import defaultdict

def resolve_domains(domains):
    # ip_occurrences will count the number of occurrences for each IP
    # ip_domains will store the domains that resolved to each IP
    ip_occurrences = defaultdict(int)
    ip_domains = defaultdict(list)

    domain_ips = {}  # stores mapping of domain to IP

    for i, domain in enumerate(domains, start=1):
        try:
            result = dns.resolver.resolve(domain.strip(), 'A')  # 'A' record for IPv4 addresses
            for ipval in result:
                ip = ipval.to_text()
                ip_occurrences[ip] += 1
                ip_domains[ip].append(domain.strip())
                domain_ips[domain] = ip
        except Exception as e:
            print(f'Unable to resolve {domain}: {e}')
        print(f"\rResolving Domains: {i}/{len(domains)}  {int((i/len(domains))*100)}%", end='')

    # Sort IPs by the number of occurrences (from most common to least common)
    sorted_ips = sorted(ip_occurrences.items(), key=lambda x: x[1], reverse=True)

    return domain_ips, sorted_ips, ip_domains


def main():
    parser = argparse.ArgumentParser(description='Resolve domains to IPs.')
    parser.add_argument('-f', '--file', help='File containing list of domains to resolve', required=True)
    parser.add_argument('-o', '--output', help='Output file to save the results', required=False)

    args = parser.parse_args()

    domains = set()
    with open(args.file, 'r') as f:
        for row in f:
            domains.add(row.strip())

    domain_ips, sorted_ips, ip_domains = resolve_domains(domains)

    output_lines = []
    for domain, ip in domain_ips.items():
        output_lines.append(f'{domain} : {ip}')

    output_lines.append("=====================================")

    for ip, count in sorted_ips:
        output_lines.append(f'IP: {ip}, Occurrences: {count}, Domains: {", ".join(ip_domains[ip])}')

    if args.output:
        with open(args.output, 'w') as f:
            for line in output_lines:
                f.write(line + '\n')
    else:
        for line in output_lines:
            print(line)

if __name__ == "__main__":
    main()
