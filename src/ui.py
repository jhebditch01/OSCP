import json
import os
from datetime import datetime
from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Markdown, Static, Tree, Select, TextArea, Label

# Safely import the SessionManager from storage.py
try:
    from src.storage import SessionManager
except ImportError:
    try:
        from storage import SessionManager
    except ImportError:
        SessionManager = None

# Safely import the shared NmapParser from parser.py
try:
    from src.parser import NmapParser
except ImportError:
    from parser import NmapParser


class OSCPChecklistApp(App):
    """Interactive TUI for OSCP Methodology, Nmap Parsing, and Report Generation."""

    TITLE = "OSCP Interactive Copilot"
    SUB_TITLE = "State-Driven Methodology Engine"

    CSS = """
    Screen { layout: vertical; }
    #target-setup { height: auto; padding: 1 2; background: $panel; border-bottom: heavy$accent; }
    #workspace { height: 1fr; }
    #sidebar { width: 35%; height: 100%; border-right: heavy $accent; background:$panel; }
    
    #main-content { width: 65%; height: 100%; padding: 1 2; }
    
    #target-banner { height: 3; content-align: center middle; background: $primary-background; border-bottom: solid$accent; text-style: bold; }
    #xml-action-bar { height: auto; padding: 1 0; margin-top: 1; border-top: solid $accent; }
    #xml-path-input { width: 75%; }
    #parse-xml-btn { width: 25%; }
    #notes-container { height: auto; padding: 1 0; border-top: solid $accent; margin-top: 1; display: none; }
    #notes-container.-visible { display: block; }
    #task-notes { height: 10; margin-bottom: 1; }
    """

    BINDINGS = [
        ("q", "quit", "Quit"),
        ("c", "toggle_complete", "Toggle Complete"),
        ("r", "generate_report", "Generate Report"),
    ]

    def __init__(self, target_ip=None, scan_path=None):
        super().__init__()
        self.target_ip = target_ip or "10.10.10.15"
        self.target_os = "Unknown OS"
        self.ports_data = []
        self.session = None
        self.scan_path = scan_path

    def compose(self) -> ComposeResult:
        yield Header(show_clock=True)

        with Horizontal(id="target-setup"):
            yield Input(placeholder="Target IP (10.10.10.15)...", id="ip-input", value=self.target_ip)
            yield Input(placeholder="Lab Name (e.g. ALICE)...", id="lab-input")
            yield Button("Load / Create", id="load-btn", variant="primary")
            
            session_options = []
            if SessionManager:
                session_options = [
                    (f"{s['name']} - {s['ip']}", s['session_id']) 
                    for s in SessionManager.list_active_sessions()
                ]
            
            yield Select(options=session_options, prompt="Resume Session...", id="session-select")
            yield Button("Live Report (v)", id="report-btn", variant="warning")

        with Horizontal(id="workspace"):
            with Container(id="sidebar"):
                yield Static(f"🎯 Target: {self.target_ip} | 🖥️ OS: {self.target_os}", id="target-banner")
                yield Tree("Methodology Pipeline", id="checklist-tree")
            
            # Using standard VerticalScroll so the Y-axis scrolls, but X-axis text wraps
            with VerticalScroll(id="main-content"):
                yield Markdown("# Welcome to OSCP Copilot\n\nLoad a target or parse an XML scan below.", id="task-view")
                
                with Container(id="notes-container"):
                    yield Label("📝 Operational Notes for this Task:", id="notes-label")
                    yield TextArea(id="task-notes")
                    yield Button("Save Note", id="save-note-btn", variant="primary")

                with Horizontal(id="xml-action-bar"):
                    yield Input(placeholder="Path to XML file (e.g., scans/scan.xml)...", id="xml-path-input")
                    yield Button("Analyze XML", id="parse-xml-btn", variant="success")
        yield Footer()

    def on_mount(self) -> None:
        if self.target_ip:
            self.load_target(self.target_ip)
        if self.scan_path:
            self.query_one("#xml-path-input", Input).value = self.scan_path
            self.process_xml_input()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "load-btn":
            ip_val = self.query_one("#ip-input", Input).value.strip()
            lab_val = self.query_one("#lab-input", Input).value.strip()
            if ip_val:
                if SessionManager:
                    self.session = SessionManager(target_ip=ip_val, target_name=lab_val)
                self.load_target(ip_val)
        elif event.button.id == "parse-xml-btn":
            self.process_xml_input()
        elif event.button.id == "report-btn":
            self.action_generate_report()
        elif event.button.id == "save-note-btn":
            tree = self.query_one("#checklist-tree", Tree)
            node = tree.cursor_node
            if node and isinstance(node.data, dict):
                task_id = node.data.get("id")
                note_text = self.query_one("#task-notes", TextArea).text
                if self.session and task_id:
                    self.session.mark_completed(task_id, notes=note_text)
                    self.query_one("#notes-label", Label).update("📝 Operational Notes for this Task: [green](Saved!)[/green]")

    def _generate_ports_table(self) -> str:
        if not self.ports_data:
            return "_No open ports discovered. Provide an Nmap XML scan to populate this table._"

        table = "| Port | Service |\n| :--- | :------ |\n"
        for p in self.ports_data:
            table += f"| `{p['port']}` | **{p['service'].upper()}** |\n"
        return table

    def process_xml_input(self) -> None:
        xml_val = self.query_one("#xml-path-input", Input).value.strip()
        if not xml_val: 
            return
        
        target_path = xml_val if os.path.exists(xml_val) else os.path.join("scans", xml_val)
        markdown_widget = self.query_one("#task-view", Markdown)

        if not os.path.exists(target_path):
            markdown_widget.update(f"⚠️ **Error:** Could not locate XML at `{target_path}`.")
            return

        try:
            parsed_data = NmapParser.parse_xml(target_path)
            if parsed_data and parsed_data.get("ip"):
                self.target_ip = parsed_data["ip"]
                self.target_os = parsed_data.get("os", "Unknown OS")
                self.ports_data = parsed_data.get("ports", [])
                
                self.query_one("#target-banner", Static).update(f"🎯 Target: {self.target_ip} | 🖥️ OS: {self.target_os}")
                self.query_one("#ip-input", Input).value = self.target_ip
                self.rebuild_tree()
                
                table_md = self._generate_ports_table()
                markdown_widget.update(f"# Scan Analysis Complete 🎉\n\n**Detected OS:** `{self.target_os}`\n\n### Discovered Open Ports\n\n{table_md}\n\nSelect items in the tree on the left to view commands.")
        except Exception as e:
            markdown_widget.update(f"⚠️ **Parsing Error:** {str(e)}")

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
        self.query_one("#target-banner", Static).update(f"🎯 Target: {self.target_ip} | 🖥️ OS: {self.target_os}")
        
        if not self.ports_data:
            self.ports_data = [] 

        self.rebuild_tree()
        
        markdown_widget = self.query_one("#task-view", Markdown)
        if self.ports_data:
            table_md = self._generate_ports_table()
            markdown_widget.update(f"# Target Loaded: {self.target_ip}\n\n**Detected OS:** `{self.target_os}`\n\n### Discovered Open Ports\n\n{table_md}\n\nSelect items in the tree on the left to view commands.")
        else:
            markdown_widget.update(f"# Target Loaded: {self.target_ip}\n\nProvide an XML scan below to discover services.")

    def _add_task_leaf(self, parent_node, task_data):
        is_completed = False
        task_id = task_data.get("id")
        
        if self.session and task_id and task_id in self.session.state.get("completed_tasks", []):
            is_completed = True
            
        title = task_data.get('title', 'Task')
        if is_completed:
            leaf = parent_node.add_leaf(f"[X] [line-through]{title}[/line-through]")
        else:
            leaf = parent_node.add_leaf(f"[ ] {title}")
            
        leaf.data = task_data
        return leaf

    def rebuild_tree(self) -> None:
        tree = self.query_one("#checklist-tree", Tree)
        tree.clear()
        tree.root.expand()

        recon = tree.root.add("1. Initial Reconnaissance", expand=True)
        baseline_schema = self.load_json_methodology("data/baseline.json")
        
        if baseline_schema and "tasks" in baseline_schema:
            for task in baseline_schema["tasks"]:
                self._add_task_leaf(recon, task)
        else:
            recon.add_leaf(f"[ ] Nmap Fast Scan ({self.target_ip})")
            recon.add_leaf(f"[ ] Nmap Full TCP (-p-) ({self.target_ip})")

        services = tree.root.add("2. Discovered Services", expand=True)
        if not self.ports_data:
            services.add_leaf("⚠️ No XML provided. Awaiting scan data.")
        else:
            for p in self.ports_data:
                port = str(p["port"])
                svc = str(p.get("service", "unknown")).lower()
                
                if svc == "microsoft-ds":
                    svc = "smb"
                
                node = services.add(f"Port {port} ({svc.upper()})", expand=True)
                schema = self.load_json_methodology(f"data/methodologies/{port}_{svc}.json")
                
                if schema:
                    if "categories" in schema:
                        for cat in schema["categories"]:
                            cat_node = node.add(cat.get("category", "Category"), expand=False)
                            for t in cat.get("tasks", []):
                                self._add_task_leaf(cat_node, t)
                    else:
                        tasks = schema.get("tasks", schema.get("checklist", []))
                        for t in tasks:
                            self._add_task_leaf(node, t)
                else:
                    node.add_leaf("[ ] Banner Grabbing & Enum")

        post = tree.root.add("3. Post-Exploitation", expand=False)

        post_ex_files = [
            "data/post_exploitation_windows.json",
            "data/post_exploitation_linux.json",
            "data/post_exploitation_pivoting.json",
        ]
        for filepath in post_ex_files:
            schema = self.load_json_methodology(filepath)
            if schema and "os_environments" in schema:
                for env in schema["os_environments"]:
                    env_node = post.add(env.get("os", "Environment"), expand=False)
                    for cat in env.get("categories", []):
                        cat_node = env_node.add(cat.get("category", "Category"), expand=False)
                        for t in cat.get("tasks", []):
                            self._add_task_leaf(cat_node, t)
            else:
                post.add_leaf(f"⚠️ Missing {filepath}")

    def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
        data = getattr(event.node, "data", None)
        md = self.query_one("#task-view", Markdown)
        notes_container = self.query_one("#notes-container", Container)
        text_area = self.query_one("#task-notes", TextArea)
        notes_label = self.query_one("#notes-label", Label)
        
        notes_label.update("📝 Operational Notes for this Task:")
        
        if data and isinstance(data, dict):
            task_id = data.get("id")
            content = f"# {data.get('title', 'Task')}\n\n"
            
            if data.get("description"):
                content += f"*{data.get('description')}*\n\n"
                
            content += "### Commands:\n\n```bash\n"
            for cmd in data.get("commands", []):
                formatted_cmd = cmd.replace('{target_ip}', self.target_ip)
                content += f"{formatted_cmd}\n"
            content += "```\n"
            content += "---\n*Press `c` to toggle completion status.*"
            md.update(content)

            notes_container.add_class("-visible")
            if self.session and task_id and task_id in self.session.state.get("notes", {}):
                text_area.text = self.session.state["notes"][task_id]
            else:
                text_area.text = ""
        else:
            label = str(event.node.label).replace("[ ] ", "").replace("[X] ", "")
            md.update(f"# Category: {label}\n\nTarget IP: `{self.target_ip}`\nSelect a sub-task to view executable commands.")
            notes_container.remove_class("-visible")

    def action_toggle_complete(self) -> None:
        tree = self.query_one("#checklist-tree", Tree)
        node = tree.cursor_node
        if node and not node.children and isinstance(node.data, dict):
            label = str(node.label)
            task_id = node.data.get("id")
            
            if label.startswith("[ ]"):
                node.set_label(f"[X] [line-through]{label[4:]}[/line-through]")
                if self.session and task_id:
                    current_notes = self.query_one("#task-notes", TextArea).text
                    self.session.mark_completed(task_id, notes=current_notes)
                    
            elif label.startswith("[X]"):
                # Rich markup like [line-through] is consumed into styling during
                # rendering, so str(node.label) never contains those tags as text —
                # only the literal "[X] " prefix needs stripping here.
                clean = label[4:].strip()
                node.set_label(f"[ ] {clean}")
                if self.session and task_id:
                    self.session.remove_completed(task_id)

    def action_generate_report(self) -> None:
        tree = self.query_one("#checklist-tree", Tree)
        report_lines = [
            f"# Engagement Report: {self.target_ip}",
            f"*Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}*",
            f"**Detected OS:** `{self.target_os}`\n",
            "## Successful Enumeration Steps\n",
        ]

        def parse_completed(node):
            if not node.children and str(node.label).startswith("[X]"):
                title = str(node.label)[4:].strip()
                report_lines.append(f"### {title}")
                if isinstance(node.data, dict):
                    # Output keeps the standard block format for the final report
                    report_lines.append("```bash")
                    for cmd in node.data.get("commands", []):
                        report_lines.append(cmd.replace("{target_ip}", self.target_ip))
                    report_lines.append("```")
                report_lines.append("")
            for child in node.children:
                parse_completed(child)

        parse_completed(tree.root)
        
        os.makedirs("sessions", exist_ok=True)
        out_file = f"sessions/report_{self.target_ip.replace('.', '_')}.md"
        with open(out_file, "w", encoding="utf-8") as f:
            f.write("\n".join(report_lines))

        self.query_one("#task-view", Markdown).update(f"✅ **Report Saved Successfully!**\n\nOutput file: `{out_file}`")