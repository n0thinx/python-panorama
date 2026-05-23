#!/usr/bin/env python3
"""
Palo Alto Firewall - Multi Device-Group Address & Policy Manager
Creates address objects and security policies across multiple device groups.
"""

import requests
import json
import argparse
import csv
from typing import Optional

requests.packages.urllib3.disable_warnings()


class PaloAltoMultiDG:
    def __init__(self, host: str, api_key: str, vsys: str = "vsys1", panorama_host: Optional[str] = None,
                 device_groups: Optional[list[str]] = None):
        self.host = host
        self.api_key = api_key
        self.vsys = vsys
        self.panorama_host = panorama_host
        self.default_device_groups = device_groups or []
        self.session = requests.Session()
        self.session.headers.update({'X-PAN-KEY': api_key})

        if panorama_host:
            self.base_url = f"https://{panorama_host}/restapi/v11.2"
        else:
            self.base_url = f"https://{host}/restapi/v11.2"

    def _make_url(self, endpoint: str) -> str:
        return f"{self.base_url}{endpoint}"

    def create_address(self, name: str, ip_netmask: str,
                       device_groups: list[str], description: str = "") -> dict:
        """Create address object in specified device groups."""
        results = {}
        body = {
            "entry": {
                "@name": name,
                "ip-netmask": ip_netmask,
            }
        }
        if description:
            body["entry"]["description"] = description

        for dg in device_groups:
            params = {
                'location': 'device-group',
                'device-group': dg,
                'name': name
            }
            url = self._make_url("/Objects/Addresses")
            resp = self.session.post(url, params=params, json=body, verify=False)
            results[dg] = {
                'status': resp.status_code,
                'response': resp.json() if resp.ok else resp.text
            }
        return results

    def create_address_group(self, name: str, addresses: list[str],
                             device_groups: list[str], description: str = "") -> dict:
        """Create address group in specified device groups."""
        results = {}
        body = {
            "entry": {
                "@name": name,
                "static": {"member": addresses}
            }
        }
        if description:
            body["entry"]["description"] = description

        for dg in device_groups:
            params = {
                'location': 'device-group',
                'device-group': dg,
                'name': name
            }
            url = self._make_url("/Objects/AddressGroups")
            resp = self.session.post(url, params=params, json=body, verify=False)
            results[dg] = {
                'status': resp.status_code,
                'response': resp.json() if resp.ok else resp.text
            }
        return results

    def create_security_rule(self, rule_name: str, source_zone: str,
                             dest_zone: str, source_address: list[str],
                             dest_address: list[str], application: list[str],
                             service: str, action: str,
                             device_groups: list[str], description: str = "",
                             rulebase: str = "pre-rulebase") -> dict:
        """Create security policy rule in specified device groups."""
        results = {}
        body = {
            "entry": {
                "@name": rule_name,
                "from": {"member": [source_zone]},
                "to": {"member": [dest_zone]},
                "source": {"member": source_address},
                "destination": {"member": dest_address},
                "application": {"member": application},
                "service": {"member": [service]},
                "action": action,
                "description": description,
            }
        }

        for dg in device_groups:
            params = {
                'location': 'device-group',
                'device-group': dg,
                'name': rule_name
            }
            url = self._make_url(f"/Policies/SecurityRules")
            resp = self.session.post(url, params=params, json=body, verify=False)
            results[dg] = {
                'status': resp.status_code,
                'response': resp.json() if resp.ok else resp.text
            }
        return results

    def list_addresses(self, device_group: str) -> list:
        """List all address objects in a device group."""
        params = {'location': 'device-group', 'device-group': device_group}
        url = self._make_url("/Objects/Addresses")
        resp = self.session.get(url, params=params, verify=False)
        if resp.ok:
            return resp.json().get('result', {}).get('entry', [])
        return []

    def list_device_groups(self) -> list:
        """List all device groups."""
        url = self._make_url("/Objects/DeviceGroups")
        resp = self.session.get(url, verify=False)
        if resp.ok:
            return resp.json().get('result', {}).get('entry', [])
        return []

    def import_addresses_from_csv(self, csv_path: str) -> dict:
        """
        Import addresses from CSV file.
        CSV format: name,ip,description,device_group

        Example:
        google_dns,8.8.4.4,Google Public DNS,DG-US
        cloudflare_dns,1.1.1.1,Cloudflare DNS,DG-EU
        """
        results = {}
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('name', '').strip()
                ip = row.get('ip', '').strip()
                desc = row.get('description', '').strip()
                dg = row.get('device_group', '').strip()
                if not dg:
                    dg = ','.join(self.default_device_groups)
                dg_list = [g.strip() for g in dg.split(',') if g.strip()]
                if name and ip and dg_list:
                    result = self.create_address(name, ip, dg_list, desc)
                    results[name] = result
        return results


def main():
    parser = argparse.ArgumentParser(description="Palo Alto Multi Device-Group Manager")
    parser.add_argument("--host", required=True, help="Panorama/PA Firewall IP")
    parser.add_argument("--api-key", required=True, help="API Key")
    parser.add_argument("--panorama", help="Panorama host (if connecting via Panorama)")
    parser.add_argument("--device-groups", nargs="+", help="Device groups (optional, used as default for CSV if not in file)")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Address subcommand
    addr_parser = subparsers.add_parser("address", help="Create address object")
    addr_parser.add_argument("--name", required=True)
    addr_parser.add_argument("--ip", required=True, help="IP or network")
    addr_parser.add_argument("--description", default="")

    # Address group subcommand
    agroup_parser = subparsers.add_parser("address-group", help="Create address group")
    agroup_parser.add_argument("--name", required=True)
    agroup_parser.add_argument("--addresses", nargs="+", required=True)
    agroup_parser.add_argument("--description", default="")

    # Policy subcommand
    policy_parser = subparsers.add_parser("policy", help="Create security rule")
    policy_parser.add_argument("--name", required=True)
    policy_parser.add_argument("--src-zone", required=True)
    policy_parser.add_argument("--dst-zone", required=True)
    policy_parser.add_argument("--src-addr", nargs="+", required=True)
    policy_parser.add_argument("--dst-addr", nargs="+", required=True)
    policy_parser.add_argument("--app", nargs="+", required=True)
    policy_parser.add_argument("--service", required=True, default="application-default")
    policy_parser.add_argument("--action", required=True, choices=["allow", "deny", "drop"])
    policy_parser.add_argument("--description", default="")

    # CSV import subcommand
    csv_parser = subparsers.add_parser("csv-import", help="Import addresses from CSV")
    csv_parser.add_argument("--csv-file", required=True, help="Path to CSV file")

    args = parser.parse_args()

    pa = PaloAltoMultiDG(args.host, args.api_key, panorama_host=args.panorama,
                  device_groups=args.device_groups)

    if args.command == "address":
        result = pa.create_address(args.name, args.ip, args.device_groups, args.description)
    elif args.command == "address-group":
        result = pa.create_address_group(args.name, args.addresses, args.device_groups, args.description)
    elif args.command == "policy":
        result = pa.create_security_rule(
            args.name, args.src_zone, args.dst_zone,
            args.src_addr, args.dst_addr, args.app,
            args.service, args.action, args.device_groups, args.description
        )
    elif args.command == "csv-import":
        result = pa.import_addresses_from_csv(args.csv_file)
    else:
        print("Specify a command: address, address-group, policy, csv-import")
        return

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()