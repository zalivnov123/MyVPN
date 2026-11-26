#!/usr/bin/env python3
"""Generate a new VPN user: token, mobile config + QR, deploy to server.

Usage: python scripts/gen-user.py <username>
Creates users/<name>/<name>-mobile.json and users/<name>/<name>-qr.png,
adds the user to configs/server.json and reloads the server.
"""
import json
import os
import secrets
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SERVER_JSON = os.path.join(ROOT, "configs", "server.json")
SERVER_HOST = "64.176.74.108"
SSH_PORT = "442"
SSH_KEY = os.path.expandvars(r"%USERPROFILE%\.ssh\vultr_vpn")


def run(cmd):
    print("+", " ".join(cmd))
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        sys.exit(1)
    return r


def main():
    if len(sys.argv) != 2 or not sys.argv[1].isidentifier():
        print("usage: python scripts/gen-user.py <username>  (latin letters, e.g. friend2)")
        sys.exit(1)
    name = sys.argv[1]

    cfg = json.load(open(SERVER_JSON, encoding="utf-8"))
    cfg.setdefault("users", {})
    if name in cfg["users"]:
        print(f"user {name} already exists")
        sys.exit(1)

    token = secrets.token_hex(24)
    cfg["users"][name] = token
    json.dump(cfg, open(SERVER_JSON, "w", encoding="utf-8"), indent=2)
    print(f"token for {name}: {token}")

    outdir = os.path.join(ROOT, "users", name)
    os.makedirs(outdir, exist_ok=True)
    qr = os.path.join(outdir, f"{name}-qr.png")
    js = os.path.join(outdir, f"{name}-mobile.json")
    run([os.path.join(ROOT, "qrgen.exe"), "-token", token, "-qr", qr, "-json", js])

    # Deploy
    run(["scp", "-i", SSH_KEY, "-P", SSH_PORT, "-o", "BatchMode=yes",
         SERVER_JSON, f"root@{SERVER_HOST}:/etc/vpn/server.json"])
    run(["ssh", "-i", SSH_KEY, "-p", SSH_PORT, "-o", "BatchMode=yes",
         f"root@{SERVER_HOST}", "systemctl restart vpn-server && systemctl is-active vpn-server"])

    print(f"\nDone. Files for {name}:")
    print("  QR:  ", qr)
    print("  JSON:", js)


if __name__ == "__main__":
    main()
