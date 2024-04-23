import json
from typing import Iterable, Optional
import click

import stix2_explorer.converter as converter


@click.group()
@click.option("--indent", default=4)
@click.pass_context
def main(ctx: click.Context, indent: int):
    ctx.obj = {"indent": indent}


@main.command("triples")
@click.argument("paths", nargs=-1)
@click.option("--allow-deprecated/--no-deprecated", default=False, show_default=True)
@click.option("--allow-revoked/--no-revoked", default=False, show_default=True)
@click.option("--separator", default="\t", show_default=True)
@click.option("--tabs", is_flag=True)
def get_triples(
    paths: Iterable[str],
    allow_deprecated: bool,
    allow_revoked: bool,
    separator: str,
    tabs: bool,
):
    """
    Get triples.
    """
    rows = iter_objects(
        paths=paths, allow_deprecated=allow_deprecated, allow_revoked=allow_revoked
    )
    g = converter.stix2_objects_to_networkx(rows)
    triples = converter.nx_digraph_to_triples(g)

    separator = "\t" if tabs else separator
    for a, t, b in triples:
        print(f"{a}{separator}{t}{separator}{b}")


@main.command("quads")
@click.argument("paths", nargs=-1)
@click.option("--namespace", required=True)
@click.option("--allow-deprecated/--no-deprecated", default=False, show_default=True)
@click.option("--allow-revoked/--no-revoked", default=False, show_default=True)
@click.option("--separator", default="\t", show_default=True)
@click.option("--tabs", is_flag=True)
def get_quads(
    paths: Iterable[str],
    namespace: str,
    allow_deprecated: bool,
    allow_revoked: bool,
    separator: str,
    tabs: bool,
):
    """
    Get quads.
    """
    rows = iter_objects(
        paths=paths, allow_deprecated=allow_deprecated, allow_revoked=allow_revoked
    )
    g = converter.stix2_objects_to_networkx(rows)
    triples = converter.nx_digraph_to_triples(g)

    separator = "\t" if tabs else separator
    for a, t, b in triples:
        print(f"{namespace}{separator}{a}{separator}{t}{separator}{b}")


def iter_objects(paths: Iterable[str], allow_deprecated: bool, allow_revoked: bool):
    if not paths:
        raise click.UsageError("No data sources specified")

    data_source = converter.get_data_source(paths)
    rows = converter.iter_stix2_objects(
        data_source=data_source,
        ignore_deprecated=allow_deprecated is False,
        ignore_revoked=allow_revoked is False,
    )
    yield from rows


@main.command("aliases")
@click.argument("paths", nargs=-1)
@click.option("--allow-deprecated/--no-deprecated", default=False, show_default=True)
@click.option("--allow-revoked/--no-revoked", default=False, show_default=True)
@click.option("--include-names/--no-names", default=True, show_default=True)
@click.option("--lowercase/--no-lowercase", default=True, show_default=True)
@click.option(
    "--output-format", type=click.Choice(["json", "csv", "tsv"]), default="json"
)
@click.option("--separator")
@click.option("--tabs", is_flag=True)
@click.pass_context
def get_aliases(
    ctx: click.Context,
    paths: Iterable[str],
    allow_deprecated: bool,
    allow_revoked: bool,
    include_names: bool,
    lowercase: bool,
    output_format: str,
    separator: Optional[str],
    tabs: bool,
):
    """
    Get map of names/aliases/external IDs to object UUIDs.
    """
    if not paths:
        raise click.UsageError("No data sources specified")

    data_source = converter.get_data_source(paths)
    rows = tuple(
        converter.iter_stix2_objects(
            data_source=data_source,
            ignore_deprecated=allow_deprecated is False,
            ignore_revoked=allow_revoked is False,
        )
    )
    m = converter.get_alias_map(rows, include_names=include_names, lowercase=lowercase)
    if output_format == "json":
        print(json.dumps(m, sort_keys=True, indent=ctx.obj["indent"]))
    elif output_format in ["csv", "tsv"]:
        separator = "\t" if tabs else separator
        if separator:
            pass
        elif output_format == "csv":
            separator = ","
        elif output_format == "tsv":
            separator = "\t"
        else:
            raise click.UsageError(f"Unsupported output format: {output_format}")

        for alias, stix2_id in sorted(m.items()):
            print(f"{alias}{separator}{stix2_id}")

    else:
        raise click.UsageError(f"Unsupported output format: {output_format}")
