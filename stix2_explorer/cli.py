import json
from typing import Any, Iterable, Optional
from stix2_explorer import converter
import click

from stix2_explorer.constants import (
    MITRE_ATTACK_ENTERPRISE_PATH,
    MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_PATH,
    MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_URL,
    MITRE_ATTACK_ENTERPRISE_URL,
    MITRE_ATTACK_ICS_PATH,
    MITRE_ATTACK_ICS_URL,
    MITRE_ATTACK_MOBILE_PATH,
    MITRE_ATTACK_MOBILE_URL,
    MITRE_CAPEC_PATH,
    MITRE_CAPEC_URL,
    MITRE_MBC_PATH,
    MITRE_MBC_URL,
    NIST_SP_800_53_PATH,
    NIST_SP_800_53_URL,
)


@click.group()
@click.option("--include-all", is_flag=True)
@click.option("--include-mitre-attack-enterprise", is_flag=True)
@click.option("--include-mitre-attack-mobile", is_flag=True)
@click.option("--include-mitre-attack-ics", is_flag=True)
@click.option("--include-nist-sp-800-53", is_flag=True)
@click.option("--include-mitre-capec", is_flag=True)
@click.option("--include-mitre-mbc", is_flag=True)
@click.pass_context
def main(
    ctx: click.Context,
    include_all: bool,
    include_mitre_attack_enterprise: bool,
    include_mitre_attack_mobile: bool,
    include_mitre_attack_ics: bool,
    include_nist_sp_800_53: bool,
    include_mitre_capec: bool,
    include_mitre_mbc: bool,
):
    data_sources = []

    if include_all:
        include_mitre_attack_enterprise = True
        include_mitre_attack_mobile = True
        include_mitre_attack_ics = True
        include_nist_sp_800_53 = True
        include_mitre_capec = True
        include_mitre_mbc = True

    if include_mitre_attack_enterprise:
        data_source = converter.get_stix2_data_source_with_fallback(
            MITRE_ATTACK_ENTERPRISE_PATH, MITRE_ATTACK_ENTERPRISE_URL
        )
        data_sources.append(data_source)

    if include_mitre_attack_mobile:
        data_source = converter.get_stix2_data_source_with_fallback(
            MITRE_ATTACK_MOBILE_PATH, MITRE_ATTACK_MOBILE_URL
        )
        data_sources.append(data_source)

    if include_mitre_attack_ics:
        data_source = converter.get_stix2_data_source_with_fallback(
            MITRE_ATTACK_ICS_PATH, MITRE_ATTACK_ICS_URL
        )
        data_sources.append(data_source)

    if include_nist_sp_800_53:
        data_source = converter.get_stix2_data_source_with_fallback(
            NIST_SP_800_53_PATH, NIST_SP_800_53_URL
        )
        data_sources.append(data_source)

    if include_mitre_attack_enterprise and include_nist_sp_800_53:
        data_source = converter.get_stix2_data_source_with_fallback(
            MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_PATH,
            MITRE_ATTACK_ENTERPRISE_TO_NIST_SP_800_53_URL,
        )
        data_sources.append(data_source)

    if include_mitre_capec:
        data_source = converter.get_stix2_data_source_with_fallback(
            MITRE_CAPEC_PATH, MITRE_CAPEC_URL
        )
        data_sources.append(data_source)

    if include_mitre_mbc:
        data_source = converter.get_stix2_data_source_with_fallback(
            MITRE_MBC_PATH, MITRE_MBC_URL
        )
        data_sources.append(data_source)

    ctx.obj = {"data_sources": data_sources}


@main.command()
@click.option(
    "--output-format", "-f", type=click.Choice(["lines", "bundle"]), default="lines"
)
@click.option("--output-path", "-o")
@click.option("--indent", type=int, default=4)
@click.pass_context
def list_objects(
    ctx: click.Context, output_format: str, output_path: Optional[str], indent: int
):
    rows = converter.iter_stix2_objects(ctx.obj["data_sources"])
    if output_format == "bundle":
        bundle = converter.create_stix2_bundle(rows)
        write_json(data=bundle, path=output_path, indent=indent)
    else:
        write_jsonl(rows=rows, path=output_path)


@main.command()
@click.option("--output-path", "-o")
@click.option(
    "--node-label-type",
    type=click.Choice(
        ["id", "name", "type", "external-id"], default="id", show_default=True
    ),
)
@click.pass_context
def list_relationships(
    ctx: click.Context,
    output_path: Optional[str],
    node_label_type: str,
):
    rows = converter.iter_stix2_objects(ctx.obj["data_sources"])
    triples = converter.convert_stix2_objects_to_triples(rows)

    write_csv(rows=triples, path=output_path)


def write_csv(rows: Iterable[Iterable[str]], path: Optional[str]):
    if path:
        with open(path, "w") as output_file:
            for row in rows:
                output_file.write(",".join(row) + "\n")
    else:
        for row in rows:
            print(",".join(row))


def write_json(data: Any, path: Optional[str] = None, indent: Optional[int] = 4):
    blob = json.dumps(data, indent=indent)
    if path:
        with open(path, "w") as output_file:
            output_file.write(blob)
    else:
        print(blob)


def write_jsonl(rows: Iterable[dict], path: Optional[str]):
    if path:
        with open(path, "w") as output_file:
            for row in rows:
                output_file.write(json.dumps(row) + "\n")
    else:
        for row in rows:
            print(json.dumps(row))


@main.command()
@click.pass_context
def to_dot(ctx: click.Context):
    pass
