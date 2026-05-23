#!/usr/bin/env python3
"""
Palo Alto Firewall - Service Object Manager
Creates service objects from CLI or CSV across multiple device groups.
"""

import requests
import json
import argparse
import csv
from typing import Optional

requests.packages.urllib3.disable_warnings()


class PaloAltoService:
    def __init__(self, host: str, api_key: str, panorama_host: Optional[str] = None,
                 device_groups: Optional[list[str]] = None):
        self.host = host
        self.api_key = api_key
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

    def create_service(self, name: str, protocol: str, port: str,
                    device_groups: list[str], description: str = "",
                    source_port: str = None) -> dict:
        """Create service object in specified device groups."""
        results = {}
        protocol = protocol.upper()
        body = {
            "entry": {
                "@name": name,
                "protocol": {
                    "tcp": {"port": port}
                } if protocol == "TCP" else {"udp": {"port": port}}
            }
        }
        if description:
            body["entry"]["description"] = description
        if source_port:
            if protocol == "TCP":
                body["entry"]["protocol"]["tcp"]["source-port"] = source_port
            else:
                body["entry"]["protocol"]["udp"]["source-port"] = source_port

        for dg in device_groups:
            params = {
                'location': 'device-group',
                'device-group': dg,
                'name': name
            }
            url = self._make_url("/Objects/Services")
            resp = self.session.post(url, params=params, json=body, verify=False)
            results[dg] = {
                'status': resp.status_code,
                'response': resp.json() if resp.ok else resp.text
            }
        return results

    def create_service_group(self, name: str, services: list[str],
                      device_groups: list[str], description: str = "") -> dict:
        """Create service group in specified device groups."""
        results = {}
        body = {
            "entry": {
                "@name": name,
                "static": {"member": services}
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
            url = self._make_url("/Objects/ServiceGroups")
            resp = self.session.post(url, params=params, json=body, verify=False)
            results[dg] = {
                'status': resp.status_code,
                'response': resp.json() if resp.ok else resp.text
            }
        return results

    def list_services(self, device_group: str) -> list:
        """List all service objects in a device group."""
        params = {'location': 'device-group', 'device-group': device_group}
        url = self._make_url("/Objects/Services")
        resp = self.session.get(url, params=params, verify=False)
        if resp.ok:
            return resp.json().get('result', {}).get('entry', [])
        return []

    def import_from_csv(self, csv_path: str) -> dict:
        """
        Import services from CSV file.

        CSV format:
        name,protocol,port,source_port,description,device_group

        Example:
        http,TCP,80,,HTTP service,DG-US
        https,TCP,443,,HTTPS service,DG-US
        dns,UDP,53,,DNS service,DG-EU

        For service-group:
        name,protocol,,,description,members,device_group
        web-services,TCP,,,,http;https;dns,DG-US
        """
        results = {}
        with open(csv_path, 'r') as f:
            reader = csv.DictReader(f)
            for row in reader:
                name = row.get('name', '').strip()
                protocol = row.get('protocol', '').strip().upper()
                port = row.get('port', '').strip()
                source_port = row.get('source_port', '').strip()
                desc = row.get('description', '').strip()
                members_str = row.get('members', '').strip()
                dg = row.get('device_group', '').strip()

                if not dg:
                    dg = ','.join(self.default_device_groups)
                dg_list = [g.strip() for g in dg.split(',') if g.strip()]

                if not name or not dg_list:
                    continue

                # Check for service-group
                if members_str:
                    members = [m.strip() for m in members_str.split(';') if m.strip()]
                    result = self.create_service_group(name, members, dg_list, desc)
                elif protocol and port:
                    result = self.create_service(name, protocol, port, dg_list, desc, source_port or None)
                else:
                    result = {'error': 'Missing protocol or port'}
                results[name] = result
        return results


def main():
    parser = argparse.ArgumentParser(description="Palo Alto Service Object Manager")
    parser.add_argument("--host", required=True, help="Panorama/PA Firewall IP")
    parser.add_argument("--api-key", required=True, help="API Key")
    parser.add_argument("--panorama", help="Panorama host")
    parser.add_argument("--device-groups", nargs="+", help="Device groups")

    subparsers = parser.add_subparsers(dest="command", help="Commands")

    # Create service subcommand
    svc_parser = subparsers.add_parser("create", help="Create service object")
    svc_parser.add_argument("--name", required=True)
    svc_parser.add_argument("--protocol", required=True, choices=["TCP", "UDP"])
    svc_parser.add_argument("--port", required=True, help="Port or range")
    svc_parser.add_argument("--source-port", help="Source port (optional)")
    svc_parser.add_argument("--description", default="")

    # Service group subcommand
    grp_parser = subparsers.add_parser("service-group", help="Create service group")
    grp_parser.add_argument("--name", required=True)
    grp_parser.add_argument("--services", nargs="+", required=True)
    grp_parser.add_argument("--description", default="")

    # List subcommand
    list_parser = subparsers.add_parser("list", help="List services")
    list_parser.add_argument("--dg", required=True)

    # CSV import subcommand
    csv_parser = subparsers.add_parser("csv-import", help="Import services from CSV")
    csv_parser.add_argument("--csv-file", required=True)

    args = parser.parse_args()

    pa = PaloAltoService(args.host, args.api_key, args.panorama, args.device_groups)

    if args.command == "create":
        result = pa.create_service(args.name, args.protocol, args.port,
                            args.device_groups, args.description, args.source_port)
    elif args.command == "service-group":
        result = pa.create_service_group(args.name, args.services,
                                 args.device_groups, args.description)
    elif args.command == "list":
        result = pa.list_services(args.dg)
    elif args.command == "csv-import":
        result = pa.import_from_csv(args.csv_file)
    else:
        print("Specify a command: create, service-group, list, csv-import")
        return

    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()