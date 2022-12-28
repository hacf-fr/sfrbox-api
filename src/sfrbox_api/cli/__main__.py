"""Command-line interface."""
import click


@click.command()
@click.version_option()
def main() -> None:
    """SFR Box API."""


if __name__ == "__main__":
    main(prog_name="sfrbox-api")  # pragma: no cover
