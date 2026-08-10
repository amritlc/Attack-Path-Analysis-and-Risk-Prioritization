from pathlib import Path
import csv
import xml.etree.ElementTree as ET

RAW = Path("data/raw/nmap")
OUT = Path("data/processed/lab/inventory")

hosts = {}
services = {}

# read every Nmap XML file.
for file in RAW.glob("*.xml"):
    root = ET.parse(file).getroot()

    for host in root.findall("host"):
        address = host.find("address[@addrtype='ipv4']")
        if address is None:
            continue

        ip = address.get("addr")
        hostname = host.find("hostnames/hostname")
        os_match = host.find("os/osmatch")

        # Duplicate hosts are removed by IP.
        hosts[ip] = {
            "ip": ip,
            "hostname": hostname.get("name") if hostname is not None else "",
            "os": os_match.get("name") if os_match is not None else "",
        }

        for port in host.findall("ports/port"):
            state = port.find("state")

            # I keep only open ports.
            if state is None or state.get("state") != "open":
                continue

            service = port.find("service")
            key = (ip, port.get("portid"), port.get("protocol"))

            services[key] = {
                "ip": ip,
                "port": port.get("portid"),
                "protocol": port.get("protocol"),
                "service": service.get("name", "") if service is not None else "",
                "product": service.get("product", "") if service is not None else "",
                "version": service.get("version", "") if service is not None else "",
            }

OUT.mkdir(parents=True, exist_ok=True)

# The host inventory is saved.
with open(OUT / "hosts.csv", "w", newline="") as f:
    writer = csv.DictWriter(f, fieldnames=["ip", "hostname", "os"])
    writer.writeheader()
    writer.writerows(hosts.values())

# The service inventory is saved.
with open(OUT / "services.csv", "w", newline="") as f:
    writer = csv.DictWriter(
        f,
        fieldnames=["ip", "port", "protocol", "service", "product", "version"],
    )
    writer.writeheader()
    writer.writerows(services.values())

print(f"Hosts: {len(hosts)}")
print(f"Open services: {len(services)}")