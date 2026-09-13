import json
import os
from datetime import datetime
import xml.etree.ElementTree as ET
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Markdown, Static, Tree

def parse_nmap_xml(xml_path: str):
    """Safely parses Nmap XML files for IP and open ports."""
    if not os.path.exists(xml_path):
        return None
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        target_ip = "Unknown Target"
        ports_data = []

        host = root.find("host")
        if host is not None:
            address = host.find("address[@addrtype='ipv4']")
            if address is not None:
                target_ip = address.get("addr")

            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is not None and state_elem.get("state") == "open":
                    port_id = port_elem.get("portid")
                    service_elem = port_elem.find("service")
                    service_name = service_elem.get("name", "unknown") if service_elem is not None else "unknown"
                    ports_data.append({"port": port_id, "service": service_name})

        return {"ip": target_ip, "ports": ports_data}
    except Exception:
        return None

class OSCPChecklistApp(App):
    """Interactive TUI for OSCP Methodology and Enumeration Tracking."""

    TITLE = "OSCP Interactive Copilot"
    SUB_TITLE = "State-Driven Methodology Engine"
    
    CSS = """
    Screen { layout: vertical; }
    #target-setup { height: auto; padding: 1 2; background: $panel; border-bottom: heavy $accent; }
    #workspace { height: 1fr; }
    #sidebar { width: 35%; height: 100%; border-right: heavy $accent; background: $panel; }
    #main-content { width: 65%; height: 100%; padding: 1 2; }
    #target-banner { height: 3; content-align: center middle; background: $primary-background; border-bottom: solid $accent; text-style: bold; }
    #xml-action-bar { height: auto; padding: 1 0; margin-top: 1; border-top: solid $accent; }
    #xml-path-input { width: 75%; }
    #parse-xml-btn { width: 25%; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("d", "defer_task", "Defer Task"),
        ("c", "toggle_complete", "Toggle Complete"),
        ("r", "generate_report", "Generate Report"),
    ]

    def __init__(self, target_ip=None):
        super().__init__()
        self.target_ip = target_ip or "10.10.10.15"
        self.ports_data = []

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="target-setup"):
            yield Input(placeholder="Enter Target IP (e.g. 10.10.10.15)...", id="ip-input")
            yield Button("Load Target", id="load-btn", variant="primary")

        with Horizontal(id="workspace"):
            with Container(id="sidebar"):
                yield Static("🎯 Target: None Set", id="target-banner")
                yield Tree("Methodology Pipeline", id="checklist-tree")
            with VerticalScroll(id="main-content"):
                yield Markdown("# Welcome to OSCP Copilot\n\nEnter a target IP address or parse an XML scan below.", id="task-view")
                
                # The restored XML action bar
                with Horizontal(id="xml-action-bar"):
                    yield Input(placeholder="Path to XML file (e.g., scans/scan.xml)...", id="xml-path-input")
                    yield Button("Analyze XML", id="parse-xml-btn", variant="success")
        yield Footer()

    def on_mount(self) -> None:
        if self.target_ip:
            self.load_target(self.target_ip)

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load-btn":
            input_widget = self.query_one("#ip-input", Input)
            if input_widget.value.strip():
                self.load_target(input_widget.value.strip())
        elif event.button.id == "parse-xml-btn":
            self.process_xml_input()

    def on_input_submitted(self, event: Input.Submitted) -> None:
        if event.input.id == "ip-input" and event.value.strip():
            self.load_target(event.value.strip())
        elif event.input.id == "xml-path-input" and event.value.strip():
            self.process_xml_input()

    def _generate_ports_table(self) -> str:
        if not self.ports_data:
            return "_No open ports discovered. Provide an Nmap XML scan to populate this table._"

        table = "| Port | Service |\n| :--- | :------ |\n"
        for p in self.ports_data:
            table += f"| `{p['port']}` | **{p['service'].upper()}** |\n"
        return table

    def process_xml_input(self) -> None:
        xml_val = self.query_one("#xml-path-input", Input).value.strip()
        if not xml_val: return
        
        target_path = xml_val if os.path.exists(xml_val) else os.path.join("scans", xml_val)
        markdown_widget = self.query_one("#task-view", Markdown)

        if not os.path.exists(target_path):
            markdown_widget.update(f"⚠️ **Error:** Could not locate XML at `{target_path}`.")
            return

        parsed_data = parse_nmap_xml(target_path)
        if parsed_data and parsed_data.get("ip"):
            self.target_ip = parsed_data["ip"]
            self.ports_data = parsed_data.get("ports", [])
            
            self.query_one("#target-banner", Static).update(f"🎯 Target: {self.target_ip} (XML Loaded)")
            self.query_one("#ip-input", Input).value = self.target_ip
            self.rebuild_tree()
            
            table_md = self._generate_ports_table()
            markdown_widget.update(f"# Scan Analysis Complete 🎉\n\n### Discovered Open Ports\n\n{table_md}\n\nSelect items in the tree on the left to view commands.")

    def load_json_methodology(self, filepath: str):
        if not os.path.exists(filepath):
            return None
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            return None

    def load_target(self, ip_address: str) -> None:
        self.target_ip = ip_address
        self.ports_data = [] 
        self.query_one("#target-banner", Static).update(f"🎯 Target: {self.target_ip}")
        self.rebuild_tree()
        self.query_one("#task-view", Markdown).update(f"# Target Loaded: {self.target_ip}\n\nProvide an XML scan below to discover services.")

    def rebuild_tree(self) -> None:
        tree = self.query_one("#checklist-tree", Tree)
        tree.clear()
        tree.root.expand()

        recon = tree.root.add("1. Initial Reconnaissance", expand=True)
        recon.add_leaf(f"[ ] Nmap Fast Scan ({self.target_ip})")
        recon.add_leaf(f"[ ] Nmap Full TCP (-p-) ({self.target_ip})")

        services = tree.root.add("2. Discovered Services", expand=True)
        if not self.ports_data:
            services.add_leaf("⚠️ No XML provided.")
        else:
            for p in self.ports_data:
                port = str(p["port"])
                svc = str(p.get("service", "unknown")).lower()
                
                node = services.add(f"Port {port} ({svc.upper()})", expand=True)
                schema = self.load_json_methodology(f"data/methodologies/{port}_{svc}.json")
                
                if schema:
                    tasks = schema.get("tasks", schema.get("checklist", []))
                    for t in tasks:
                        leaf = node.add_leaf(f"[ ] {t.get('title', 'Task')}")
                        leaf.data = t
                else:
                    node.add_leaf("[ ] Banner Grabbing & Enum")

        post = tree.root.add("3. Post-Exploitation")
        post.add_leaf("[ ] Local Enum (PrivEsc)")

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = getattr(event.node, "data", None)
        md = self.query_one("#task-view", Markdown)
        
        if data and isinstance(data, dict):
            content = f"# {data.get('title', 'Task')}\n\n"
            if data.get("description"):
                content += f"*{data.get('description')}*\n\n"
            content += "### Executable Commands:\n```bash\n"
            for cmd in data.get("commands", []):
                content += f"{cmd.replace('{target_ip}', self.target_ip)}\n\n"
            content += "```\n\n*Press `c` to toggle completion status.*"
            md.update(content)
        else:
            label = str(event.node.label).replace("[ ] ", "").replace("[X] [line-through]", "").replace("[/line-through]", "").strip()
            md.update(f"# Category: {label}\n\nTarget IP: `{self.target_ip}`\n\n*Select a specific leaf task to view commands.*")

    def action_toggle_complete(self) -> None:
        tree = self.query_one("#checklist-tree", Tree)
        node = tree.cursor_node
        if node and node.is_leaf:
            label = str(node.label)
            if label.startswith("[ ]"):
                node.set_label(f"[X] [line-through]{label[4:]}[/line-through]")
            elif label.startswith("[X]"):
                clean = label.replace("[X] [line-through]", "").replace("[/line-through]", "").strip()
                node.set_label(f"[ ] {clean}")

    def action_generate_report(self) -> None:
        tree = self.query_one("#checklist-tree", Tree)
        report_lines = [
            f"# Penetration Test Report - {self.target_ip}",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*\n",
            "## Successful Enumeration Steps\n",
        ]

        def parse_completed(node):
            if not node.children and str(node.label).startswith("[X]"):
                clean_title = str(node.label).replace("[X] [line-through]", "").replace("[/line-through]", "").strip()
                report_lines.append(f"### {clean_title}")

                node_data = getattr(node, "data", None)
                if node_data and isinstance(node_data, dict):
                    report_lines.append("```bash")
                    for cmd in node_data.get("commands", []):
                        report_lines.append(cmd.replace("{target_ip}", self.target_ip))
                    report_lines.append("```")
                report_lines.append("")
            for child in node.children:
                parse_completed(child)

        parse_completed(tree.root)
        os.makedirs("sessions", exist_ok=True)
        report_path = f"sessions/report_{self.target_ip.replace('.', '_')}.md"
        with open(report_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))

        self.query_one("#task-view", Markdown).update(
            f"# Report Generated Successfully!\n\nSaved markdown report to: `{report_path}`"
        )