import subprocess
import json
import sys

def main():
    if len(sys.argv) < 2:
        print("Please provide the domain file name as a command line argument.")
        print("Usage: python tls_analysis.py domain_file.txt")
        return

    domain_file = sys.argv[1]

    # Create a list of command arguments
    args = ["tlsx", "-l", domain_file, "-ve", "-ce", "-ct", "all", "-c", "700", "-j", "-o", "output.json"]

    # Run the command
    subprocess.run(args, stdout=subprocess.PIPE, text=True)

    # Parse the output
    parse_output()


def parse_output():
    deprecated_protocols = {"ssl30", "ssl20", "tls10", "tls11"}

    tls_versions = {
        "ssl30": "SSL 3.0",
        "ssl20": "SSL 2.0",
        "tls10": "TLS 1.0",
        "tls11": "TLS 1.1",
        "tls12": "TLS 1.2",
        "tls13": "TLS 1.3"
    }

    tls_protocols = {}
    weak_ciphers = {}

    with open('output.json', 'r') as file:
        for line in file:
            try:
                data = json.loads(line)
                host = data.get('host')
                ip = data.get('ip')
                version_enum = data.get('version_enum', [])
                cipher_enum = data.get('cipher_enum', [])

                for version in version_enum:
                    if version in deprecated_protocols:
                        if host not in tls_protocols:
                            tls_protocols[host] = {'ip': ip, 'protocols': []}
                        tls_protocols[host]['protocols'].append(tls_versions[version])

                for cipher_data in cipher_enum:
                    weak = cipher_data.get('ciphers', {}).get('weak', [])
                    protocol = cipher_data.get('version')

                    for weak_cipher in weak:
                        if host not in weak_ciphers:
                            weak_ciphers[host] = {'ip': ip, 'protocols': {}}
                        if protocol not in weak_ciphers[host]['protocols']:
                            weak_ciphers[host]['protocols'][protocol] = []
                        weak_ciphers[host]['protocols'][protocol].append(weak_cipher)

            except json.JSONDecodeError:
                print(f"Error parsing JSON: {line}")

    for host, data in tls_protocols.items():
        print(f"Host: {host} ({data['ip']})")
        print("Deprecated TLS protocols:", ', '.join(data['protocols']))
        print()

    for host, data in weak_ciphers.items():
        print(f"**Host:** {host} ({data['ip']})")
        for protocol, ciphers in data['protocols'].items():
            print(f"**Protocol:** {tls_versions.get(protocol, protocol)}")
            print("**Weak Ciphers:**\n")
            print("```")
            for cipher in ciphers:
                print(cipher)
            print("```")
        print()


if __name__ == "__main__":
    main()
