import json
import os
import re
from typing import Dict, List, Optional


class SessionManager:
  """Manages per-target session state, switching, and report generation."""

  def __init__(self, target_ip: str, target_name: Optional[str] = None):
    self.target_ip = target_ip.strip()
    self.target_name = (
        target_name.strip().upper() if target_name else "UNKNOWN"
    )

    # Sanitize session key for filesystem safety
    safe_ip = re.sub(r"[^\w\.-]", "_", self.target_ip)
    safe_name = re.sub(r"[^\w\.-]", "_", self.target_name)
    self.session_id = (
        f"{safe_ip}_{safe_name}" if target_name else f"{safe_ip}"
    )

    self.session_file = f"sessions/{self.session_id}_session.json"
    self.report_file = f"sessions/{self.session_id}_report.md"

    self.state = {
        "session_id": self.session_id,
        "target_ip": self.target_ip,
        "target_name": self.target_name,
        "completed_tasks": [],
        "command_history": [],
        "notes": {},
    }
    self.load_session()

  def load_session(self) -> None:
    """Loads existing target state if available."""
    if os.path.exists(self.session_file):
      try:
        with open(self.session_file, "r") as f:
          self.state = json.load(f)
      except Exception as e:
        print(f"[!] Error loading session {self.session_file}: {e}")

  def save_session(self) -> None:
    """Persists current state to disk."""
    os.makedirs("sessions", exist_ok=True)
    with open(self.session_file, "w") as f:
      json.dump(self.state, f, indent=4)

  def mark_completed(
      self, task_id: str, command_run: str = "", notes: str = ""
  ) -> None:
    """Records task completion, commands executed, and notes."""
    if task_id not in self.state["completed_tasks"]:
      self.state["completed_tasks"].append(task_id)

    if command_run and command_run not in self.state["command_history"]:
      self.state["command_history"].append(command_run)

    if notes:
      self.state["notes"][task_id] = notes

    self.save_session()

  def remove_completed(self, task_id: str) -> None:
    """Unchecks a completed task."""
    if task_id in self.state["completed_tasks"]:
      self.state["completed_tasks"].remove(task_id)
      self.save_session()

  def generate_report(self) -> str:
    """Exports an engagement report for the active target."""
    os.makedirs("sessions", exist_ok=True)

    report_content = (
        f"# OSCP Engagement Report\n\n"
        f"**Target Host:** `{self.target_name}`\n"
        f"**Target IP:** `{self.target_ip}`\n"
        f"**Session Identifier:** `{self.session_id}`\n\n"
        f"---\n\n"
        f"## 1. Executive Summary\n"
        f"Target enumeration and exploitation log for `{self.target_ip}` ({self.target_name}).\n\n"
        f"## 2. Completed Checklist Items\n"
    )

    if self.state["completed_tasks"]:
      for task in self.state["completed_tasks"]:
        report_content += f"- [x] {task}\n"
    else:
      report_content += "No tasks marked completed yet.\n"

    report_content += "\n## 3. Command Execution History\n"
    if self.state["command_history"]:
      report_content += "```bash\n"
      for cmd in self.state["command_history"]:
        report_content += f"{cmd}\n"
      report_content += "```\n"
    else:
      report_content += "No commands logged.\n"

    report_content += "\n## 4. Operational Findings & Notes\n"
    if self.state["notes"]:
      for task_id, note in self.state["notes"].items():
        report_content += f"### Task: {task_id}\n{note}\n\n"
    else:
      report_content += "No custom notes recorded.\n"

    with open(self.report_file, "w") as f:
      f.write(report_content)

    return self.report_file

  @staticmethod
  def list_active_sessions() -> List[Dict[str, str]]:
    """Scans sessions/ directory to list all available target sessions."""
    sessions = []
    if not os.path.exists("sessions"):
      return sessions

    for file in os.listdir("sessions"):
      if file.endswith("_session.json"):
        filepath = os.path.join("sessions", file)
        try:
          with open(filepath, "r") as f:
            data = json.load(f)
            sessions.append({
                "session_id": data.get("session_id", file),
                "ip": data.get("target_ip", "Unknown"),
                "name": data.get("target_name", "Unknown"),
            })
        except Exception:
          continue
    return sessions