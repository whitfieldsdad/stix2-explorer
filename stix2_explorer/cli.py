import click


@click.group()
@click.option("--indent", default=4)
@click.pass_context
def main(ctx: click.Context, indent: int):
    ctx.obj = {"indent": indent}
