import click

from config.config import Configs
from utils.session import create_tables
from pentest import run_vulnbot

from utils.log_common import build_logger

logger = build_logger()


@click.group(help="VulnBot")
def main():
    ...


@main.command("init")
def init():
    Configs.set_auto_reload(False)
    logger.success(f"Start initializing the project data directory：{Configs.PENTEST_ROOT}")
    Configs.basic_config.make_dirs()
    logger.success("Creating all data directories: Success.")

    create_tables()
    logger.success("Initializing database: Success.")

    Configs.create_all_templates()
    Configs.set_auto_reload(True)

    logger.success("Generating default configuration file: Success.")


@main.command("start")
def start():
    from startup import main as startup_main

    return startup_main.main(standalone_mode=False)


@main.command("vulnbot")
@click.option("-m", "--max_interactions", "max_interactions", default=5, help="Maximum interactions per role")
@click.option("--task-prompt", "task_prompt", default="", help="Non-interactive initial pentest task prompt.")
@click.option("--no-preload", "no_preload", is_flag=True, help="Skip the previous-session prompt.")
@click.option("--no-save", "no_save", is_flag=True, help="Skip the save-session prompt at the end.")
@click.option("--session-name", "session_name", default="", help="Session name to use when saving non-interactively.")
@click.option("--print-init-description", "print_init_description", is_flag=True, help="Print the final initial description and exit.")
def vulnbot(max_interactions, task_prompt, no_preload, no_save, session_name, print_init_description):
    return run_vulnbot(
        max_interactions=max_interactions,
        task_prompt=task_prompt,
        no_preload=no_preload,
        no_save=no_save,
        session_name=session_name,
        print_init_description=print_init_description,
    )


@main.command("pentestgpt")
@click.pass_context
def pentestgpt(ctx):
    from experiment.pentestgpt import main as pentestgpt_main

    return ctx.invoke(pentestgpt_main)


@main.command("base")
@click.pass_context
def base(ctx):
    from experiment.base import main as base_main

    return ctx.invoke(base_main)



if __name__ == "__main__":
    main()
