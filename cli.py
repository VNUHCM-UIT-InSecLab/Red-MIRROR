import click

from pentest import main as pentest_main

from utils.log_common import build_logger

logger = build_logger()


@click.group(help="MIRROR - Multi-agent Introspective Reasoning for Robust Offensive Research")
def main():
    ...


@main.command("init")
def init():
    from config.config import Configs
    from utils.session import create_tables

    Configs.set_auto_reload(False)
    create_tables()
    logger.success("Initializing database: Success.")

    Configs.create_all_templates()
    Configs.set_auto_reload(True)

    logger.success("Generating default configuration file: Success.")


@main.command("start")
@click.option("-a", "--all", "all", is_flag=True, help="run api.py and webui.py")
@click.option("--api", "api", is_flag=True, help="run api.py")
@click.option("-w", "--webui", "webui", is_flag=True, help="run webui.py server")
def start(all, api, webui):
    from startup import main as startup_main

    startup_main.callback(all, api, webui)


main.add_command(pentest_main, "autopentest")

if __name__ == "__main__":
    main()
