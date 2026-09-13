import os
import xml.etree.ElementTree as ET

class NmapParser:
    """Parses Nmap XML output (-oX) into structured Python dictionaries."""
    
    @staticmethod
    def parse_xml(xml_path: str):
        if not os.path.exists(xml_path):
            return None

        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            target_ip = "Unknown Target"
            ports_data = []

            # Find host IP address
            host = root.find("host")
            if host is None:
                return None

            address = host.find("address[@addrtype='ipv4']")
            if address is not None:
                target_ip = address.get("addr")

            # Extract open ports and service names
            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is not None and state_elem.get("state") == "open":
                    port_id = port_elem.get("portid")
                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"

                    ports_data.append({
                        "port": port_id,
                        "service": service_name
                    })

            return {
                "ip": target_ip,
                "ports": ports_data
            }
        except Exception:
            return None