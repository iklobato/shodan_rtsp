import json
from pprint import pprint

import nmap


class NmapScanner:
    def __init__(self):
        self.nm = nmap.PortScanner()

    def scan(self, target):
        response = self.nm.scan(hosts=target, arguments='-p 80,554 -sV')
        return response


# if __name__ == "__main__":

    # brasil_ip_range = "200.128.0.0/9"
    #
    # scanner = NmapScanner()
    # hosts = scanner.scan("177.136.94.105/24")
    #
    # with open('nmap_result.json', 'w') as f:
    #     f.write(json.dumps(hosts))
    # pprint(f"Hosts found: {hosts['scan'].keys()}")
    #
    # for h in hosts['scan']:
    #     for port in hosts['scan'][h]['tcp']:
    #         print({
    #             'host': h,
    #             'port': port,
    #             'state': hosts['scan'][h]['tcp'][port]['state'],
    #             'name': hosts['scan'][h]['tcp'][port]['name'],
    #         })

    # open_ports = scanner.get_open_ports(target_ip)
    # for host, ports in open_ports.items():
    #     print(f"Open ports on {host}: {ports}")
