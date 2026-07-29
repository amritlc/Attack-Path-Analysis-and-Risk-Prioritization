from __future__ import annotations

import csv
import ipaddress
import xml.etree.ElementTree as ET
from pathlib import Path


PROJECT_ROOT = Path(__file__).resolve().parents[1]
RAW_DIR = PROJECT_ROOT / "data" / "raw" / "nmap"
OUTPUT_DIR = PROJECT_ROOT / "data" / "processed"

OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

host_records: dict[str, dict[str, str]] = {}
service_records: dict[tuple[str, str, int], dict[str, str | int]] = {}


def ip_sort_key(value: str) -> ipaddress.IPv4Address:
    return ipaddress.ip_address(value)


def get_address(host: ET.Element, address_type: str) -> tuple[str, str]:
    for address in host.findall("address"):
        if address.get("addrtype") == address_type:
            return address.get("addr", ""), address.get("vendor", "")
    return "", ""


def get_hostname(host: ET.Element) -> str:
    hostname = host.find("./hostnames/hostname")
    return hostname.get("name", "") if hostname is not None else ""


def get_best_os(host: ET.Element) -> tuple[str, str]:
    matches = host.findall("./os/osmatch")

    if not matches:
        return "", ""

    best_match = max(
        matches,
        key=lambda item: int(item.get("accuracy", "0"))
    )

    return (
        best_match.get("name", ""),
        best_match.get("accuracy", "")
    )


def parse_hosts(xml_file: Path) -> None:
    root = ET.parse(xml_file).getroot()

    for host in root.findall("host"):
        ip_address, _ = get_address(host, "ipv4")

        if not ip_address:
            continue

        mac_address, vendor = get_address(host, "mac")
        hostname = get_hostname(host)
        os_guess, os_accuracy = get_best_os(host)

        status_element = host.find("status")
        status = (
            status_element.get("state", "")
            if status_element is not None
            else ""
        )

        record = host_records.setdefault(
            ip_address,
            {
                "ip_address": ip_address,
                "hostname": "",
                "mac_address": "",
                "vendor": "",
                "status": "",
                "os_guess": "",
                "os_accuracy": "",
                "source_files": "",
            },
        )

        if hostname:
            record["hostname"] = hostname
        if mac_address:
            record["mac_address"] = mac_address
        if vendor:
            record["vendor"] = vendor
        if status:
            record["status"] = status
        if os_guess:
            record["os_guess"] = os_guess
            record["os_accuracy"] = os_accuracy

        existing_sources = set(
            filter(None, record["source_files"].split(";"))
        )
        existing_sources.add(xml_file.name)
        record["source_files"] = ";".join(sorted(existing_sources))


def parse_services(xml_file: Path) -> None:
    root = ET.parse(xml_file).getroot()

    for host in root.findall("host"):
        ip_address, _ = get_address(host, "ipv4")

        if not ip_address:
            continue

        for port_element in host.findall("./ports/port"):
            state_element = port_element.find("state")
            state = (
                state_element.get("state", "")
                if state_element is not None
                else ""
            )

            if state != "open":
                continue

            protocol = port_element.get("protocol", "")
            port = int(port_element.get("portid", "0"))

            service = port_element.find("service")

            cpe_values: list[str] = []

            if service is not None:
                cpe_values = [
                    cpe.text.strip()
                    for cpe in service.findall("cpe")
                    if cpe.text
                ]

            key = (ip_address, protocol, port)

            service_records[key] = {
                "ip_address": ip_address,
                "protocol": protocol,
                "port": port,
                "state": state,
                "service_name": (
                    service.get("name", "") if service is not None else ""
                ),
                "product": (
                    service.get("product", "") if service is not None else ""
                ),
                "version": (
                    service.get("version", "") if service is not None else ""
                ),
                "extra_info": (
                    service.get("extrainfo", "") if service is not None else ""
                ),
                "tunnel": (
                    service.get("tunnel", "") if service is not None else ""
                ),
                "confidence": (
                    service.get("conf", "") if service is not None else ""
                ),
                "cpe": ";".join(cpe_values),
                "source_file": xml_file.name,
            }


def write_csv(
    output_file: Path,
    fieldnames: list[str],
    rows: list[dict],
) -> None:
    with output_file.open("w", newline="", encoding="utf-8") as csv_file:
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)


def main() -> None:
    discovery_file = RAW_DIR / "host_discovery.xml"
    full_scan_files = sorted(RAW_DIR.glob("full_tcp_*.xml"))

    if not discovery_file.exists():
        raise FileNotFoundError(
            f"Missing host discovery file: {discovery_file}"
        )

    if not full_scan_files:
        raise FileNotFoundError(
            f"No full_tcp_*.xml files found in {RAW_DIR}"
        )

    parse_hosts(discovery_file)

    for xml_file in full_scan_files:
        parse_hosts(xml_file)
        parse_services(xml_file)

    hosts = sorted(
        host_records.values(),
        key=lambda row: ip_sort_key(row["ip_address"]),
    )

    services = sorted(
        service_records.values(),
        key=lambda row: (
            ip_sort_key(str(row["ip_address"])),
            str(row["protocol"]),
            int(row["port"]),
        ),
    )

    write_csv(
        OUTPUT_DIR / "hosts.csv",
        [
            "ip_address",
            "hostname",
            "mac_address",
            "vendor",
            "status",
            "os_guess",
            "os_accuracy",
            "source_files",
        ],
        hosts,
    )

    write_csv(
        OUTPUT_DIR / "services.csv",
        [
            "ip_address",
            "protocol",
            "port",
            "state",
            "service_name",
            "product",
            "version",
            "extra_info",
            "tunnel",
            "confidence",
            "cpe",
            "source_file",
        ],
        services,
    )

    print(f"Hosts written: {len(hosts)}")
    print(f"Open services written: {len(services)}")
    print(f"Output: {OUTPUT_DIR / 'hosts.csv'}")
    print(f"Output: {OUTPUT_DIR / 'services.csv'}")


if __name__ == "__main__":
    main()