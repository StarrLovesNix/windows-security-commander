"""
ui.py - Live terminal dashboard using the Rich library.

Layout:
  ┌─ header bar ─────────────────────────────────────────────────────────┐
  │ hostname | time | cpu/mem | threat counts | unacked alert count      │
  ├─ LIVE EVENT FEED ──────────────┬─ ACTIVE CONNECTIONS ───────────────┤
  │ scrolling chronological        │ process -> remote:port              │
  │ event stream                   ├─ PINNED ALERTS ────────────────────┤
  │                                │ persistent HIGH/CRITICAL until ack'd│
  ├─ status bar ───────────────────┴────────────────────────────────────┤
  │ status message | keybinds                                           │
  └─────────────────────────────────────────────────────────────────────┘

SecurityUI.add_event()  — thread-safe, call from any monitor thread
SecurityUI.run()        — blocks until stop_event is set (live dashboard)
SecurityUI.history()    — read-only scrollable view of past events from DB
"""

import socket
import threading
import time
from collections import deque
from datetime import datetime
from typing import TYPE_CHECKING, Deque, Dict, List, Optional

import psutil
from rich import box
from rich.console import Console
from rich.layout import Layout
from rich.live import Live
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .events import EventType, SecurityEvent, Severity

if TYPE_CHECKING:
    from .alert_store import AlertStore

MAX_FEED    = 500   # Events kept in memory ring-buffer
DISPLAY_ROWS = 26   # Rows shown in live feed panel

SEVERITY_STYLE: Dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH:     "bold yellow",
    Severity.MEDIUM:   "yellow",
    Severity.LOW:      "cyan",
    Severity.INFO:     "dim white",
}

TYPE_LABEL: Dict[EventType, str] = {
    EventType.CONN_NEW:        "CONN   ",
    EventType.CONN_LISTEN:     "LISTEN ",
    EventType.DNS:             "DNS    ",
    EventType.PROC_NEW:        "PROC   ",
    EventType.PROC_SUSPICIOUS: "PROC ! ",
    EventType.LOGIN_SUCCESS:   "LOGIN  ",
    EventType.LOGIN_FAIL:      "FAIL   ",
    EventType.LOGIN_BRUTE:     "BRUTE !",
    EventType.SERVICE_NEW:     "SERVICE",
    EventType.TASK_NEW:        "TASK   ",
    EventType.AUDIT_CLEAR:     "AUDIT !",
    EventType.THREAT_IP:       "THREAT!",
    EventType.FIREWALL_BLOCK:  "BLOCKED",
    EventType.PROCESS_KILL:    "KILLED ",
    EventType.BASELINE_DEV:    "BASELN ",
    EventType.ARP_SPOOF:       "ARP !  ",
    EventType.LAN_NEW:         "LAN    ",
    EventType.POLICY_CHANGE:   "POLICY ",
}


class SecurityUI:
    def __init__(self, config: dict, alert_store: Optional["AlertStore"] = None):
        self._config       = config
        self._alert_store  = alert_store
        self._events: Deque[SecurityEvent] = deque(maxlen=MAX_FEED)
        self._threat_counts: Dict[Severity, int] = {s: 0 for s in Severity}
        self._total        = 0
        self._start        = datetime.now()
        self._status       = "Initialising monitors..."
        self._lock         = threading.Lock()
        self._console      = Console()

    # ------------------------------------------------------------------
    # Thread-safe public API

    def add_event(self, event: SecurityEvent):
        with self._lock:
            self._events.appendleft(event)
            self._total += 1
            if event.severity != Severity.INFO:
                self._threat_counts[event.severity] += 1

    def set_status(self, msg: str):
        self._status = msg

    # ------------------------------------------------------------------
    # Live dashboard

    def run(self, stop_event: threading.Event):
        """Block until stop_event is set, refreshing the dashboard at 2 fps."""
        with Live(
            self._render(),
            console=self._console,
            refresh_per_second=2,
            screen=True,
        ) as live:
            while not stop_event.is_set():
                live.update(self._render())
                time.sleep(0.5)

    # ------------------------------------------------------------------
    # History viewer (--history mode, read-only, no live updates)

    def show_history(self, rows: List[dict], title: str = "EVENT HISTORY"):
        """Render a paginated read-only view of past events from the DB."""
        PAGE = self._console.height - 8
        page = 0
        total_pages = max(1, (len(rows) + PAGE - 1) // PAGE)

        while True:
            self._console.clear()
            start = page * PAGE
            chunk = rows[start: start + PAGE]

            tbl = Table(
                show_header=True,
                header_style="bold white on grey23",
                box=box.SIMPLE_HEAVY,
                expand=True,
            )
            tbl.add_column("Timestamp",  width=20,  no_wrap=True, style="dim")
            tbl.add_column("Sev",        width=9,   no_wrap=True)
            tbl.add_column("Type",       width=8,   no_wrap=True)
            tbl.add_column("Source",     width=18,  no_wrap=True)
            tbl.add_column("Description", ratio=1)

            for row in chunk:
                try:
                    sev   = Severity(row["severity"])
                    etype = EventType(row["event_type"])
                except ValueError:
                    sev   = Severity.INFO
                    etype = EventType.CONN_NEW
                sty   = SEVERITY_STYLE.get(sev, "white")
                label = TYPE_LABEL.get(etype, row["event_type"][:7])
                fixed = " [green]✓[/green]" if row.get("remediated") else ""
                tbl.add_row(
                    row["timestamp"][:19],
                    f"[{sty}]{sev.value}[/{sty}]",
                    f"[{sty}]{label}[/{sty}]",
                    row["source"][:18],
                    f"[{sty}]{row['description'][:85]}{fixed}[/{sty}]",
                )

            self._console.print(Panel(
                tbl,
                title=f"[bold white] {title} — Page {page+1}/{total_pages} [/bold white]",
                border_style="blue",
                box=box.ROUNDED,
            ))
            self._console.print(
                "[dim]  [N]ext page   [P]rev page   [Q]uit[/dim]"
            )

            key = input().strip().lower()
            if key == "n" and page < total_pages - 1:
                page += 1
            elif key == "p" and page > 0:
                page -= 1
            elif key == "q":
                break

    # ------------------------------------------------------------------
    # Rendering

    def _render(self) -> Layout:
        h = self._console.height
        layout = Layout()
        layout.split_column(
            Layout(name="header", size=3),
            Layout(name="body",   ratio=1),
            Layout(name="footer", size=3),
        )
        layout["body"].split_row(
            Layout(name="feed",  ratio=2),
            Layout(name="right", ratio=1),
        )
        layout["right"].split_column(
            Layout(name="conns",  ratio=1),
            Layout(name="pinned", ratio=1),
        )

        layout["header"].update(self._header())
        layout["feed"].update(self._feed(max(8, h - 8)))
        layout["conns"].update(self._connections())
        layout["pinned"].update(self._pinned_alerts())
        layout["footer"].update(self._footer())
        return layout

    def _header(self) -> Panel:
        hostname = socket.gethostname()
        now    = datetime.now().strftime("%H:%M:%S")
        uptime = str(datetime.now() - self._start).split(".")[0]
        try:
            cpu = f"{psutil.cpu_percent(interval=None):.0f}%"
            mem = f"{psutil.virtual_memory().percent:.0f}%"
            hw  = f"  CPU {cpu}  MEM {mem}"
        except Exception:
            hw = ""

        pinned_count = self._alert_store.count() if self._alert_store else 0
        crit = self._threat_counts[Severity.CRITICAL]
        high = self._threat_counts[Severity.HIGH]
        med  = self._threat_counts[Severity.MEDIUM]

        t = Text()
        t.append("  Security Commander ", style="bold white")
        t.append(f"  {hostname}", style="bold cyan")
        t.append(f"  {now}", style="dim white")
        t.append(hw, style="dim white")
        t.append(f"  Events: {self._total}", style="dim white")
        t.append(f"  Up: {uptime}", style="dim white")
        t.append("  |  Threats: ")
        if crit:
            t.append(f" CRITICAL:{crit} ", style="bold red on dark_red")
        if high:
            t.append(f" HIGH:{high} ", style="bold yellow")
        if med:
            t.append(f" MEDIUM:{med} ", style="yellow")
        if not crit and not high and not med:
            t.append(" All clear ", style="bold green")
        if pinned_count:
            t.append(f"  |  Pinned: {pinned_count} unacknowledged",
                     style="bold red" if pinned_count else "dim")
        return Panel(t, style="on grey15", box=box.SIMPLE, padding=(0, 0))

    def _feed(self, height: int) -> Panel:
        tbl = Table(
            show_header=True,
            header_style="bold white on grey23",
            box=box.SIMPLE_HEAVY,
            expand=True,
            show_lines=False,
            padding=(0, 1),
        )
        tbl.add_column("Time",   width=10, no_wrap=True, style="dim")
        tbl.add_column("Type",   width=8,  no_wrap=True)
        tbl.add_column("Sev",    width=9,  no_wrap=True)
        tbl.add_column("Source", width=18, no_wrap=True)
        tbl.add_column("Description", ratio=1)

        with self._lock:
            visible = list(self._events)[: min(height - 4, DISPLAY_ROWS)]

        for ev in visible:
            sty   = SEVERITY_STYLE.get(ev.severity, "white")
            label = TYPE_LABEL.get(ev.event_type, ev.event_type.value[:7])
            fixed = " [green]✓[/green]" if ev.remediated else ""
            tbl.add_row(
                ev.timestamp.strftime("%H:%M:%S"),
                f"[{sty}]{label}[/{sty}]",
                f"[{sty}]{ev.severity.value}[/{sty}]",
                ev.source[:18],
                f"[{sty}]{ev.description[:85]}{fixed}[/{sty}]",
            )

        return Panel(
            tbl,
            title="[bold white] LIVE EVENT FEED [/bold white]",
            border_style="blue",
            box=box.ROUNDED,
        )

    def _connections(self) -> Panel:
        tbl = Table(
            show_header=True,
            header_style="bold white",
            box=box.SIMPLE,
            expand=True,
            padding=(0, 1),
        )
        tbl.add_column("Process", style="cyan",  no_wrap=True)
        tbl.add_column("Remote",  style="white", ratio=1)
        tbl.add_column("Port",    style="yellow", width=6, justify="right")

        try:
            by_proc: Dict[str, List] = {}
            for c in psutil.net_connections(kind="inet"):
                if c.status == "ESTABLISHED" and c.raddr:
                    try:
                        name = psutil.Process(c.pid).name() if c.pid else "?"
                    except Exception:
                        name = "?"
                    by_proc.setdefault(name, []).append(c.raddr)

            for proc, addrs in sorted(by_proc.items(), key=lambda x: -len(x[1]))[:10]:
                if len(addrs) == 1:
                    ip = addrs[0].ip
                    try:
                        host = socket.gethostbyaddr(ip)[0][:22]
                    except Exception:
                        host = ip
                    tbl.add_row(proc[:16], host, str(addrs[0].port))
                else:
                    tbl.add_row(proc[:16],
                                f"[dim]{len(addrs)} connections[/dim]", "")
        except psutil.AccessDenied:
            tbl.add_row("[dim]run as admin[/dim]", "", "")
        except Exception:
            pass

        return Panel(
            tbl,
            title="[bold white] ACTIVE CONNECTIONS [/bold white]",
            border_style="green",
            box=box.ROUNDED,
        )

    def _pinned_alerts(self) -> Panel:
        """
        Persistent panel showing HIGH/CRITICAL alerts that have not been
        acknowledged. Survives UI refreshes and program restarts.
        """
        body = Text()

        if self._alert_store:
            alerts = self._alert_store.get_all()
        else:
            # Fallback: show recent HIGH/CRITICAL from live feed
            with self._lock:
                alerts = [
                    {
                        "severity":    e.severity.value,
                        "description": e.description,
                        "timestamp":   e.timestamp.isoformat(),
                        "remediated":  e.remediated,
                    }
                    for e in list(self._events)[:100]
                    if e.severity in (Severity.CRITICAL, Severity.HIGH)
                ]

        if not alerts:
            body.append("  No unacknowledged alerts\n", style="bold green")
        else:
            for a in alerts[:10]:
                try:
                    sev = Severity(a["severity"])
                except ValueError:
                    sev = Severity.HIGH
                sty    = SEVERITY_STYLE.get(sev, "white")
                marker = "[bold red]●[/bold red]" if sev == Severity.CRITICAL else "[yellow]●[/yellow]"
                ts     = a.get("timestamp", "")[:19]
                fixed  = " ✓" if a.get("remediated") else ""
                body.append_text(Text.from_markup(f"  {marker} "))
                body.append(f"[{ts[11:19]}] ", style="dim")
                body.append(f"{a['description'][:50]}{fixed}\n", style=sty)

        subtitle = ""
        if self._alert_store and self._alert_store.count() > 0:
            subtitle = "  [dim]run with --acknowledge to clear[/dim]"

        return Panel(
            body,
            title="[bold white] PINNED ALERTS [/bold white]" + subtitle,
            border_style="red",
            box=box.ROUNDED,
        )

    def _footer(self) -> Panel:
        msg = Text()
        msg.append(f"  {self._status}", style="dim")
        msg.append(
            "  |  Ctrl+C to exit  |  --history to review past sessions"
            "  |  --acknowledge to clear pinned alerts",
            style="dim",
        )
        return Panel(msg, style="on grey15", box=box.SIMPLE, padding=(0, 0))
