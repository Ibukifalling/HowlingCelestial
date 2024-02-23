import click
from basic.info import *

@click.command(name="Howling_Celestial")

@click.option(
    "--info",
    default=1,
    help="获取集群状态",
)

def cli(info):
    if info:
        detect_cluster_assets()


if __name__ == "__main__":
    cli()