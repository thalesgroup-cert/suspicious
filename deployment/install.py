#!/usr/bin/env python3
"""
install.py — Suspicious platform interactive installer.

Guides the operator through every required configuration value,
writes .env and settings.json, creates the Docker network,
optionally generates TLS certificates, and starts the stack.

Requirements: questionary, rich  (installed by install.sh)
"""
from __future__ import annotations

import json
import os
import re
import secrets
import shutil
import subprocess
import sys
from pathlib import Path

try:
    import questionary
    from questionary import Style
    from rich.console import Console
    from rich.panel import Panel
    from rich.table import Table
    from rich import box
except ImportError:
    print("Missing dependencies. Run:  pip install questionary rich")
    sys.exit(1)

console = Console()

STYLE = Style([
    ("qmark",        "fg:#4FB3FF bold"),
    ("question",     "bold"),
    ("answer",       "fg:#4FB3FF bold"),
    ("pointer",      "fg:#4FB3FF bold"),
    ("highlighted",  "fg:#4FB3FF bold"),
    ("selected",     "fg:#4FB3FF"),
    ("separator",    "fg:#555555"),
    ("instruction",  "fg:#555555 italic"),
])

ENV_EXAMPLE   = Path(".env.example")
ENV_FILE      = Path(".env")
SETTINGS_FILE = Path("Suspicious/settings.json")
SETTINGS_SAMPLE = Path("Suspicious/settings-sample.json")

# ── Helpers ────────────────────────────────────────────────────────────────

def run(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, capture_output=True, text=True)


def gen_secret(length: int = 50) -> str:
    return secrets.token_urlsafe(length)


def ask(prompt: str, default: str = "", validate=None) -> str:
    kwargs = {"style": STYLE, "default": default}
    if validate:
        kwargs["validate"] = validate
    return questionary.text(prompt, **kwargs).ask() or default


def ask_password(prompt: str, confirm: bool = True) -> str:
    while True:
        pw = questionary.password(prompt, style=STYLE).ask()
        if not confirm:
            return pw
        pw2 = questionary.password("Confirm: ", style=STYLE).ask()
        if pw == pw2:
            return pw
        console.print("[red]Passwords do not match — try again.[/red]")


def ask_bool(prompt: str, default: bool = True) -> bool:
    return questionary.confirm(prompt, default=default, style=STYLE).ask()


def header(title: str) -> None:
    console.print()
    console.print(Panel(f"[bold cyan]{title}[/bold cyan]", box=box.ROUNDED))


def ok(msg: str) -> None:
    console.print(f"  [green]✓[/green] {msg}")


def warn(msg: str) -> None:
    console.print(f"  [yellow]⚠[/yellow]  {msg}")


def write_env(values: dict) -> None:
    if not ENV_EXAMPLE.exists():
        console.print(f"[red]✗ {ENV_EXAMPLE} not found — cannot write .env[/red]")
        sys.exit(1)
    template = ENV_EXAMPLE.read_text()
    for key, value in values.items():
        # Replace KEY=anything with KEY=value
        template = re.sub(
            rf"^({re.escape(key)}=).*$",
            rf"\g<1>{value}",
            template,
            flags=re.MULTILINE,
        )
    ENV_FILE.write_text(template)
    ok(f".env written ({ENV_FILE})")


def write_settings(patches: dict) -> None:
    source = SETTINGS_FILE if SETTINGS_FILE.exists() else SETTINGS_SAMPLE
    if not source.exists():
        warn(f"settings.json not found at {source} — skipping")
        return
    data = json.loads(source.read_text())
    for path, value in patches.items():
        keys = path.split(".")
        node = data
        for key in keys[:-1]:
            node = node.setdefault(key, {})
        node[keys[-1]] = value
    SETTINGS_FILE.write_text(json.dumps(data, indent=4))
    ok(f"settings.json written ({SETTINGS_FILE})")


# ── Sections ───────────────────────────────────────────────────────────────

def section_network(env: dict) -> None:
    header("1 / 7 — Network & Domain")
    console.print("  This is the domain name Traefik will serve Suspicious on.")
    console.print("  Example: [cyan]suspicious.corp.example.com[/cyan]\n")

    domain = ask("Corporate domain (FQDN): ", default="suspicious.corp.example.com",
                 validate=lambda v: "." in v or "Please enter a valid domain")
    env["DOMAIN_CORP"] = domain

    console.print("\n  [dim]Docker network settings (defaults are fine for most deployments)[/dim]")
    if ask_bool("  Customise Docker network subnet?", default=False):
        env["NETWORK_SUBNET"]  = ask("  Network subnet: ",  default=env["NETWORK_SUBNET"])
        env["NETWORK_GATEWAY"] = ask("  Gateway: ",         default=env["NETWORK_GATEWAY"])
        env["NETWORK_IP_RANGE"] = ask("  IP range: ",       default=env["NETWORK_IP_RANGE"])


def section_database(env: dict, settings: dict) -> None:
    header("2 / 7 — Database Credentials")
    console.print("  [yellow]These are set once. Changing them after first launch erases all data.[/yellow]\n")

    db_user = ask("MariaDB username: ", default="suspicious")
    db_pass = ask_password("MariaDB password: ")
    db_root = ask_password("MariaDB root password: ")

    env["MYSQL_USER"]          = db_user
    env["MYSQL_PASSWORD"]      = db_pass
    env["MYSQL_ROOT_PASSWORD"] = db_root

    settings["database.user"]          = db_user
    settings["database.password"]      = db_pass
    settings["database.root_password"] = db_root


def section_minio(env: dict, settings: dict) -> None:
    header("3 / 7 — Object Storage (MinIO / RustFS)")
    console.print("  Used to store email attachments and analysis artifacts.\n")

    minio_user = ask("MinIO access key (username): ", default="minio")
    minio_pass = ask_password("MinIO secret key (password): ")

    env["MINIO_ROOT_USER"]     = minio_user
    env["MINIO_ROOT_PASSWORD"] = minio_pass

    settings["storage.minio.access_key"] = minio_user
    settings["storage.minio.secret_key"] = minio_pass


def section_smtp(env: dict, settings: dict) -> None:
    header("4 / 7 — SMTP (Outgoing Email)")
    console.print("  Used to send analysis results to reporters.\n")

    if not ask_bool("Configure SMTP now?", default=True):
        warn("Skipped — email notifications will not work until SMTP is configured in settings.json")
        return

    smtp_server = ask("SMTP server: ", default="smtp.example.com")
    smtp_port   = ask("SMTP port: ",   default="25")
    smtp_user   = ask("SMTP username: ")
    smtp_pass   = ask_password("SMTP password: ", confirm=False)
    smtp_tls    = ask_bool("Enable TLS (STARTTLS)?", default=True)

    settings["email.smtp.server"]   = smtp_server
    settings["email.smtp.port"]     = int(smtp_port)
    settings["email.smtp.username"] = smtp_user
    settings["email.smtp.password"] = smtp_pass
    settings["email.smtp.tls"]      = smtp_tls


def section_branding(settings: dict) -> None:
    header("5 / 7 — Branding")
    console.print("  Shown in the UI header and notification emails.\n")

    company = ask("Company / team name: ", default="Security Team")
    contact = ask("Contact email: ",       default="security@example.com")
    footer  = ask("Email footer text: ",   default="Internal use only")

    settings["branding.company_name"]    = company
    settings["email.content.team_name"]  = company
    settings["branding.contact_email"]   = contact
    settings["email.content.footer"]     = footer


def section_versions(env: dict) -> None:
    header("6 / 7 — Image Versions")
    console.print("  [yellow]Pinning versions is strongly recommended for production.[/yellow]")
    console.print("  Check https://github.com/thalesgroup-cert/suspicious/releases for the latest.\n")

    current_version = env.get("SUSPICIOUS_VERSION", "latest")
    version = ask(f"Suspicious version [{current_version}]: ", default=current_version)
    env["SUSPICIOUS_VERSION"] = version

    if ask_bool("Keep default versions for all other services?", default=True):
        return

    for svc, default in [
        ("DB_SUSPICIOUS_VERSION",  "11.4"),
        ("ELASTICSEARCH_VERSION",  "8.19.7"),
        ("CORTEX_VERSION",         "4.0.0-1"),
        ("CHROMADB_VERSION",       "0.6.3"),
        ("TRAEFIK_VERSION",        "v3.3.4"),
    ]:
        env[svc] = ask(f"  {svc}: ", default=env.get(svc, default))


def section_launch(env: dict) -> None:
    header("7 / 7 — Ready to Launch")

    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key",   style="cyan")
    table.add_column("Value", style="white")
    for k in ("DOMAIN_CORP", "MYSQL_USER", "MINIO_ROOT_USER",
              "SUSPICIOUS_VERSION", "NETWORK_NAME"):
        table.add_row(k, env.get(k, "—"))
    console.print(table)

    if not ask_bool("\nWrite .env and settings.json, then start the stack?"):
        console.print("\n[yellow]Installer cancelled — no files written.[/yellow]")
        sys.exit(0)


# ── Main ───────────────────────────────────────────────────────────────────

def main() -> None:
    console.print(Panel(
        "[bold cyan]Suspicious Platform Installer[/bold cyan]\n"
        "[dim]Answer each question — press Enter to accept the default.[/dim]",
        box=box.DOUBLE_EDGE,
    ))

    # Seed defaults from .env.example
    env: dict[str, str] = {}
    if ENV_EXAMPLE.exists():
        for line in ENV_EXAMPLE.read_text().splitlines():
            if "=" in line and not line.startswith("#"):
                k, _, v = line.partition("=")
                env[k.strip()] = v.strip()

    # Always auto-generate Django secret key
    env["SECRET_KEY"] = gen_secret(50)

    settings: dict[str, object] = {}

    section_network(env, )
    section_database(env, settings)
    section_minio(env, settings)
    section_smtp(env, settings)
    section_branding(settings)
    section_versions(env)
    section_launch(env)

    # ── Write files ───────────────────────────────────────────────────────
    header("Writing configuration")
    write_env(env)
    write_settings(settings)

    # ── Docker network ────────────────────────────────────────────────────
    network_name = env.get("NETWORK_NAME", "suspicious_net")
    console.print(f"\n  Creating Docker network [cyan]{network_name}[/cyan]...")
    result = run(["docker", "network", "create",
                  "--driver", "bridge",
                  "--subnet",  env.get("NETWORK_SUBNET",  "172.20.0.0/16"),
                  "--gateway", env.get("NETWORK_GATEWAY", "172.20.0.1"),
                  "--ip-range", env.get("NETWORK_IP_RANGE", "172.20.0.0/24"),
                  network_name], check=False)
    if result.returncode == 0:
        ok(f"Network {network_name} created")
    else:
        ok(f"Network {network_name} already exists")

    # ── Run init.sh for certs, cortex config, etc. ────────────────────────
    console.print("\n  Running init.sh (certificates, Cortex config, directory checks)...")
    run(["bash", "scripts/init.sh"])
    ok("init.sh complete")

    # ── Start stack ───────────────────────────────────────────────────────
    header("Starting the stack")
    console.print("  This may take a few minutes on first run (image pull).\n")
    subprocess.run(["docker", "compose", "--env-file", ".env", "up", "-d",
                    "--remove-orphans"], check=True)

    console.print()
    console.print(Panel(
        f"[bold green]✓ Suspicious is starting up![/bold green]\n\n"
        f"  Web UI:   [cyan]https://{env.get('DOMAIN_CORP', 'your.domain')}[/cyan]\n"
        f"  API:      [cyan]https://{env.get('DOMAIN_CORP', 'your.domain')}/api/[/cyan]\n\n"
        f"  Create the first admin user:\n"
        f"  [bold]make createsuperuser[/bold]\n\n"
        f"  Follow logs:\n"
        f"  [bold]make logs[/bold]",
        box=box.ROUNDED,
        border_style="green",
    ))


if __name__ == "__main__":
    main()