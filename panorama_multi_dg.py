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
        Import objects from CSV file.

        Auto-detects address type based on columns present in each row.
        Supports explicit object_type column override.

        CSV columns (all optional except name/device_group):
        name,ip,fqdn,start_ip,end_ip,members,description,device_group,object_type

        Type detection (priority):
        1. Explicit object_type column value (use ip column for value)
        2. row has 'fqdn' value → fqdn
        3. row has 'start_ip' and 'end_ip' → ip-range
        4. row has 'members' column → address-group
        5. row has 'ip' with wildcard chars (* or ?) → ip-wildcard
        6. otherwise (has 'ip') → ip-netmask
        """
        import ipaddress

        def is_valid_ip(ip_str: str) -> bool:
            """Validate IP/IP range."""
            try:
                if '-' in ip_str:
                    start, end = ip_str.split('-')
                    ipaddress.ip_address(start.strip())
                    ipaddress.ip_address(end.strip())
                    return True
                ipaddress.ip_network(ip_str, strict=False)
                return True
            except:
                return False

        def is_valid_fqdn(fqdn_str: str) -> bool:
            """Basic FQDN validation."""
            if not fqdn_str or len(fqdn_str) > 253:
                return False
            if fqdn_str.endswith('.'):
                return True
            parts = fqdn_str.split('.')
            return all(part and len(part) <= 63 for part in parts)

        results = {}
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('name', '').strip()
                desc = row.get('description', '').strip()
                dg = row.get('device_group', '').strip()
                if not dg:
                    dg = ','.join(self.default_device_groups)
                dg_list = [g.strip() for g in dg.split(',') if g.strip()]

                if not name or not dg_list:
                    continue

                # Check for explicit object_type
                explicit_type = row.get('object_type', '').strip().lower()

                # Get all possible values
                fqdn_val = row.get('fqdn', '').strip()
                start_ip = row.get('start_ip', '').strip()
                end_ip = row.get('end_ip', '').strip()
                members_str = row.get('members', '').strip()
                ip_val = row.get('ip', '').strip()

                # Determine type based on explicit_type first, then fallback to column detection
                if explicit_type == "fqdn":
                    addr_type = "fqdn"
                    # Use ip column if fqdn column empty
                    addr_value = fqdn_val or ip_val
                elif explicit_type == "ip-range":
                    addr_type = "ip-range"
                    # Use ip column or start_ip/end_ip columns
                    if ip_val and '-' in ip_val:
                        start_ip, end_ip = ip_val.split('-')
                        start_ip, end_ip = start_ip.strip(), end_ip.strip()
                    addr_value = (start_ip, end_ip)
                elif explicit_type == "address-group":
                    addr_type = "address-group"
                    addr_value = members_str
                elif explicit_type == "ip-wildcard":
                    addr_type = "ip-wildcard"
                    addr_value = ip_val
                elif explicit_type == "ip-netmask":
                    addr_type = "ip-netmask"
                    addr_value = ip_val
                elif fqdn_val:
                    addr_type = "fqdn"
                    addr_value = fqdn_val
                elif start_ip and end_ip:
                    addr_type = "ip-range"
                    addr_value = (start_ip, end_ip)
                elif members_str:
                    addr_type = "address-group"
                    addr_value = members_str
                elif ip_val and ('*' in ip_val or '?' in ip_val):
                    addr_type = "ip-wildcard"
                    addr_value = ip_val
                elif ip_val:
                    addr_type = "ip-netmask"
                    addr_value = ip_val
                else:
                    results[name] = {'skipped': 'No valid address data found in row'}
                    continue

                # Validate before API call
                valid = True
                if addr_type == "fqdn":
                    if not addr_value or not is_valid_fqdn(addr_value):
                        valid = False
                        results[name] = {'error': f'Invalid FQDN: {addr_value}'}
                elif addr_type == "ip-range":
                    if not addr_value[0] or not addr_value[1]:
                        valid = False
                        results[name] = {'error': 'Missing start_ip or end_ip'}
                    elif not (is_valid_ip(addr_value[0]) and is_valid_ip(addr_value[1])):
                        valid = False
                        results[name] = {'error': f'Invalid IP range: {addr_value[0]}-{addr_value[1]}'}
                elif addr_type in ("ip-netmask", "ip-wildcard"):
                    if not addr_value:
                        valid = False
                        results[name] = {'error': f'Missing {addr_type} value'}

                if not valid:
                    continue

                # Create object
                if addr_type == "fqdn":
                    result = self._create_fqdn(name, addr_value, dg_list, desc)
                elif addr_type == "ip-range":
                    result = self._create_ip_range(name, addr_value[0], addr_value[1], dg_list, desc)
                elif addr_type == "address-group":
                    members = [m.strip() for m in addr_value.split(';') if m.strip()] if addr_value else []
                    result = self.create_address_group(name, members, dg_list, desc)
                elif addr_type == "ip-wildcard":
                    result = self._create_ip_wildcard(name, addr_value, dg_list, desc)
                else:
                    result = self.create_address(name, addr_value, dg_list, desc)
                results[name] = result
        return results

    def _create_fqdn(self, name: str, fqdn: str, device_groups: list[str], description: str = "") -> dict:
        """Create FQDN address object."""
        results = {}
        body = {"entry": {"@name": name, "fqdn": fqdn}}
        if description:
            body["entry"]["description"] = description
        for dg in device_groups:
            params = {'location': 'device-group', 'device-group': dg, 'name': name}
            resp = self.session.post(self._make_url("/Objects/Addresses"), params=params, json=body, verify=False)
            results[dg] = {'status': resp.status_code, 'response': resp.json() if resp.ok else resp.text}
        return results

    def _create_ip_range(self, name: str, start_ip: str, end_ip: str, device_groups: list[str], description: str = "") -> dict:
        """Create IP range address object."""
        results = {}
        body = {"entry": {"@name": name, "ip-range": f"{start_ip}-{end_ip}"}}
        if description:
            body["entry"]["description"] = description
        for dg in device_groups:
            params = {'location': 'device-group', 'device-group': dg, 'name': name}
            resp = self.session.post(self._make_url("/Objects/Addresses"), params=params, json=body, verify=False)
            results[dg] = {'status': resp.status_code, 'response': resp.json() if resp.ok else resp.text}
        return results

    def _create_ip_wildcard(self, name: str, wildcard: str, device_groups: list[str], description: str = "") -> dict:
        """Create IP wildcard address object."""
        results = {}
        body = {"entry": {"@name": name, "ip-wildcard": wildcard}}
        if description:
            body["entry"]["description"] = description
        for dg in device_groups:
            params = {'location': 'device-group', 'device-group': dg, 'name': name}
            resp = self.session.post(self._make_url("/Objects/Addresses"), params=params, json=body, verify=False)
            results[dg] = {'status': resp.status_code, 'response': resp.json() if resp.ok else resp.text}
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
    csv_parser.add_argument("--object-type", default="address", choices=["address", "address-group", "fqdn", "ip-range"],
                        help="Object type to create: address, address-group, fqdn, ip-range")

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