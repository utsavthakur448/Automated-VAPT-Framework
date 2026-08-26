import json
import typer

from rich.console import Console
from rich.text import Text

from core.target import Target
from core.engine import VAPTFramework
from core.logger import setup_logger
from modules.reporting.pdf_report import PDFReportGenerator


app = typer.Typer(name="vulnscope", help="VULNSCOPE - Automated VAPT Framework")
console = Console()


def load_config():
    with open("config/default.json", "r") as file:
        return json.load(file)


@app.command()
def scan(
    target: str = typer.Option(..., "--target", "-t", help="Authorized target for assessment")
):
    """Start a VAPT assessment."""

    config = load_config()
    logger = setup_logger()
    version = config["project"]["version"]

    target_lower = target.lower()
    assessment_type = "Web VAPT" if target_lower.startswith(
        ("http://", "https://")
    ) else "Network VAPT"

    # ==================================================
    # BANNER
    # ==================================================

    BANNER_WIDTH = 68
    INNER_WIDTH = BANNER_WIDTH - 2

    def banner_line(text=""):
        rich_text = Text.from_markup(text)
        visible_length = len(rich_text.plain)
        padding = max(0, INNER_WIDTH - visible_length)
        return f"[bold cyan]║[/bold cyan]{text}{' ' * padding}[bold cyan]║[/bold cyan]"

    console.print()

    console.print(f"[bold cyan]╔{'═' * INNER_WIDTH}╗[/bold cyan]")
    console.print(banner_line())
    console.print(banner_line("                  [bold cyan]V U L N S C O P E[/bold cyan]"))
    console.print(banner_line())
    console.print(banner_line("       [white]Automated Vulnerability Assessment Tool [/white]"))
    console.print(banner_line())
    console.print(banner_line("              [bold green]Developed by Utsav Thakur[/bold green]"))
    console.print(banner_line())
    console.print(
        banner_line(
            "  [bold yellow]Email    :[/bold yellow] "
            "[white]utsavthakur448@gmail.com[/white]"
        )
    )
    console.print(
        banner_line(
            "  [bold blue]LinkedIn :[/bold blue] "
            "[white]https://www.linkedin.com/in/utsavthakur123[/white]"
        )
    )
    console.print(
        banner_line(
            "  [bold magenta]GitHub   :[/bold magenta] "
            "[white]https://github.com/utsavthakur448[/white]"
        )
    )
    console.print(banner_line())
    console.print(f"[bold cyan]╚{'═' * INNER_WIDTH}╝[/bold cyan]")
    console.print()

    # ==================================================
    # ASSESSMENT INFORMATION
    # ==================================================

    console.print(f"Version      : {version}")
    console.print(f"Target       : {target}")
    console.print(f"Assessment   : {assessment_type}")
    console.print("Mode         : Automated")
    console.print()

    # ==================================================
    # AUTHORIZATION NOTICE
    # ==================================================

    console.print("────────────────────────────────────────────────────────────")
    console.print("[bold yellow]AUTHORIZED SECURITY ASSESSMENT[/bold yellow]")
    console.print("────────────────────────────────────────────────────────────")
    console.print()

    # ==================================================
    # INITIALIZATION
    # ==================================================

    console.print("[*] Initializing NEXUS-VAPT framework...")
    console.print("[+] Configuration loaded")
    console.print("[+] Assessment engine initialized")
    console.print("[+] Vulnerability checks loaded")
    console.print("[+] Web security engine initialized")
    console.print("[+] Risk prioritizer initialized")
    console.print()

    # ==================================================
    # START ASSESSMENT
    # ==================================================

    console.print("────────────────────────────────────────────────────────────")
    console.print("[bold cyan]STARTING SECURITY ASSESSMENT[/bold cyan]")
    console.print("────────────────────────────────────────────────────────────")
    console.print()

    # ==================================================
    # TARGET VALIDATION
    # ==================================================

    console.print("[*] Target validation")

    if not Target.validate(target):
        logger.error("Invalid target rejected | Target: %s", target)

        console.print()
        console.print("[bold red][ERROR] Invalid target[/bold red]")
        console.print(f"[red]Target: {target}[/red]")
        console.print(
            "[yellow]Target must be a valid IP address, "
            "hostname, or HTTP/HTTPS URL.[/yellow]"
        )
        console.print()
        console.print("[bold red]Assessment aborted.[/bold red]")

        raise typer.Exit(code=1)

    console.print(f"[+] Target accepted: {target}")
    console.print()
    console.print("[*] Starting network discovery...")

    # ==================================================
    # FRAMEWORK
    # ==================================================

    framework = VAPTFramework(config=config, logger=logger)

    # ==================================================
    # RUN ASSESSMENT
    # ==================================================

    try:
        result = framework.run_assessment(target)

    except ValueError as exc:
        logger.error("Assessment validation error | %s", exc)

        console.print()
        console.print("[bold red][ERROR] Assessment aborted[/bold red]")
        console.print(f"[red]{exc}[/red]")

        raise typer.Exit(code=1)

    except Exception as exc:
        logger.exception(
            "Unexpected assessment failure | Target: %s",
            target
        )

        console.print()
        console.print("[bold red][ERROR] Assessment failed[/bold red]")
        console.print(
            "[red]An unexpected error occurred during "
            "the assessment.[/red]"
        )
        console.print(f"[dim]Details: {exc}[/dim]")

        raise typer.Exit(code=1)

    # ==================================================
    # EXTRACT RESULTS
    # ==================================================

    findings = result["findings"]
    scan_result = result["scan_result"]
    network_findings = result["network_findings"]
    web_findings = result["web_findings"]
    risk_summary = result["risk_summary"]
    prioritized_findings = result["prioritized_findings"]

    # ==================================================
    # PDF REPORT
    # ==================================================

    try:
        report_generator = PDFReportGenerator()

        report_path = report_generator.generate(
            target=target,
            scan_result=scan_result,
            findings=findings,
            network_findings=network_findings,
            web_findings=web_findings,
            risk_summary=risk_summary,
            prioritized_findings=prioritized_findings
        )

    except Exception as exc:
        logger.exception(
            "PDF report generation failed | Target: %s",
            target
        )

        console.print()
        console.print("[bold red][ERROR] PDF generation failed[/bold red]")
        console.print(f"[red]Details: {exc}[/red]")

        raise typer.Exit(code=1)

    # ==================================================
    # REPORT OUTPUT
    # ==================================================

    console.print()
    console.print("────────────────────────────────────────────────────────────")
    console.print("[bold green]PDF REPORT GENERATED[/bold green]")
    console.print(f"Report: {report_path}")
    console.print("────────────────────────────────────────────────────────────")

    # ==================================================
    # ASSESSMENT COMPLETED BANNER
    # ==================================================

    END_BANNER_WIDTH = 58
    END_INNER_WIDTH = END_BANNER_WIDTH - 2

    def end_banner_line(text=""):
        rich_text = Text.from_markup(text)
        visible_length = len(rich_text.plain)
        padding = max(0, END_INNER_WIDTH - visible_length)
        return f"[bold cyan]║[/bold cyan]{text}{' ' * padding}[bold cyan]║[/bold cyan]"

    console.print()
    console.print(f"[bold cyan]╔{'═' * END_INNER_WIDTH}╗[/bold cyan]")
    console.print(end_banner_line())
    console.print(
        end_banner_line(
            "              [bold green]"
            "NEXUS-VAPT ASSESSMENT COMPLETED"
            "[/bold green]"
        )
    )
    console.print(end_banner_line())
    console.print(f"[bold cyan]╚{'═' * END_INNER_WIDTH}╝[/bold cyan]")
    console.print()


@app.command()
def version():
    """Display NEXUS-VAPT version."""

    config = load_config()
    console.print(f"NEXUS-VAPT v{config['project']['version']}")


if __name__ == "__main__":
    app()
