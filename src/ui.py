from textual.app import App, ComposeResult
from textual.containers import Container, Horizontal, VerticalScroll
from textual.widgets import Button, Footer, Header, Input, Markdown, Static, Tree


class OSCPChecklistApp(App):
  """Interactive TUI for OSCP Methodology and Enumeration Tracking."""

  TITLE = "OSCP Interactive Copilot"
  SUB_TITLE = "State-Driven Methodology Engine"
  CSS = """
    Screen {
        layout: vertical;
    }
    #target-setup {
        height: auto;
        padding: 1 2;
        background: $panel;
        border-bottom: heavy $accent;
    }
    #workspace {
        height: 1fr;
    }
    #sidebar {
        width: 35%;
        height: 100%;
        border-right: heavy $accent;
        background: $panel;
    }
    #main-content {
        width: 65%;
        height: 100%;
        padding: 1 2;
    }
    #target-banner {
        height: 3;
        content-align: center middle;
        background: $primary-background;
        border-bottom: solid $accent;
        text-style: bold;
    }
    """

  BINDINGS = [
      ("q", "quit", "Quit"),
      ("d", "defer_task", "Defer Task"),
      ("c", "toggle_complete", "Toggle Complete"),
  ]

  def __init__(self, target_ip=None):
    super().__init__()
    self.target_ip = target_ip
    self.ports_data = []

  def compose(self) -> ComposeResult:
    yield Header(show_clock=True)

    with Horizontal(id="target-setup"):
      yield Input(
          placeholder=(
              "Enter Target IP (e.g. 10.10.10.15) or Nmap XML path..."
          ),
          id="ip-input",
      )
      yield Button("Load Target", id="load-btn", variant="primary")

    with Horizontal(id="workspace"):
      with Container(id="sidebar"):
        yield Static("🎯 Target: None Set", id="target-banner")
        yield Tree("Methodology Pipeline", id="checklist-tree")
      with VerticalScroll(id="main-content"):
        yield Markdown(
            "# Welcome to OSCP Copilot\n\nEnter a target IP address or XML scan"
            " path above to generate your enumeration checklist.",
            id="task-view",
        )
    yield Footer()

  def on_mount(self) -> None:
    if self.target_ip:
      self.load_target(self.target_ip)

  def on_button_pressed(self, event: Button.Pressed) -> None:
    if event.button.id == "load-btn":
      input_widget = self.query_one("#ip-input", Input)
      if input_widget.value.strip():
        self.load_target(input_widget.value.strip())

  def on_input_submitted(self, event: Input.Submitted) -> None:
    if event.input.id == "ip-input" and event.value.strip():
      self.load_target(event.value.strip())

  def load_target(self, ip_or_path: str) -> None:
    self.target_ip = ip_or_path
    banner = self.query_one("#target-banner", Static)
    banner.update(f"🎯 Target: {self.target_ip}")

    self.ports_data = [
        {"port": "21", "service": "ftp"},
        {"port": "22", "service": "ssh"},
        {"port": "80", "service": "http"},
        {"port": "445", "service": "smb"},
    ]

    tree: Tree = self.query_one("#checklist-tree", Tree)
    tree.clear()
    tree.root.expand()

    # Phase 1: Baseline Recon
    recon_node = tree.root.add("1. Initial Reconnaissance", expand=True)
    recon_node.add_leaf(f"[ ] Nmap Fast Scan ({self.target_ip})")
    recon_node.add_leaf(f"[ ] Nmap Full TCP (-p-) ({self.target_ip})")
    recon_node.add_leaf("[ ] OS Fingerprinting")

    # Phase 2: Open Service Enumeration
    services_node = tree.root.add("2. Discovered Services", expand=True)
    for port_info in self.ports_data:
      port = port_info["port"]
      service = port_info["service"].upper()
      port_node = services_node.add(f"Port {port} ({service})")
      port_node.add_leaf("[ ] Banner Grabbing & Enum")
      port_node.add_leaf("[ ] Known Vulnerabilities / ExploitDB")

    # Phase 3: Post-Exploitation
    post_node = tree.root.add("3. Post-Exploitation")
    post_node.add_leaf("[ ] Local Enum (PrivEsc)")
    post_node.add_leaf("[ ] Dump Credentials")

    markdown_widget = self.query_one("#task-view", Markdown)
    markdown_widget.update(
        f"# Target Loaded: {self.target_ip}\n\nSelect items in the tree on the"
        " left to view steps and commands."
    )

  def on_tree_node_selected(self, event: Tree.NodeSelected) -> None:
    selected_label = str(event.node.label)
    markdown_widget = self.query_one("#task-view", Markdown)

    if "Port 21" in selected_label:
      content = (
          f"# Port 21 (FTP) Enumeration Checklist\n\n"
          f"### Recommended Commands:\n"
          f"```bash\n"
          f"# Check Anonymous Login\n"
          f"nmap --script ftp-anon,ftp-bounce -p 21 {self.target_ip}\n\n"
          f"# Connect manually\n"
          f"nc -vn {self.target_ip} 21\n"
          f"```\n\n"
          f"* [ ] Verify anonymous read/write access\n"
          f"* [ ] Download all available files for inspection\n"
      )
    elif "Port 80" in selected_label:
      content = (
          f"# Port 80 (HTTP) Enumeration Checklist\n\n"
          f"### Recommended Commands:\n"
          f"```bash\n"
          f"# Directory Brute-Forcing\n"
          f"feroxbuster -u http://{self.target_ip}/ -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt\n\n"
          f"# Technology Fingerprinting\n"
          f"whatweb http://{self.target_ip}/\n"
          f"```\n"
      )
    else:
      content = (
          f"# Active Task: {selected_label}\n\nTarget IP:"
          f" `{self.target_ip}`\n\nSelect specific port nodes to load attack"
          " commands."
      )

    markdown_widget.update(content)