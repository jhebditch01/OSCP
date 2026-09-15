import argparse
import sys
from src.ui import OSCPChecklistApp


def main():
  """CLI entry point for the OSCP Interactive Methodology Engine."""
  parser = argparse.ArgumentParser(
      description="OSCP Interactive Methodology Engine - State-Driven Pentest Copilot"
  )

  parser.add_argument(
      "-t",
      "--target",
      help="Target IP address (default: 10.10.10.15)",
      default="10.10.10.15",
      type=str,
  )

  parser.add_argument(
      "-s",
      "--scan",
      help="Path to Nmap XML output file (e.g., scans/target.xml)",
      required=False,
      type=str,
  )

  parser.add_argument(
      "-k",
      "--kali-ip",
      help="Your attacker (Kali) IP address, pre-filled into command templates",
      required=False,
      type=str,
  )

  args = parser.parse_args()

  # Launch the Textual UI Application
  app = OSCPChecklistApp(target_ip=args.target, scan_path=args.scan, kali_ip=args.kali_ip)
  app.run()


if __name__ == "__main__":
  main()