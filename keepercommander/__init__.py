import sys
import click

from keepercommander import cli, display, api

__version__ = '0.2.7'

@click.group()
@click.option('--user', '-u', envvar='KEEPER_USER', help='Email address for the account')
@click.option('--password', '-p', envvar='KEEPER_PASSWORD', help='Master password for the account')
@click.option('--config', help='Config file to use')
@click.option('--debug', type=bool, help='Turn on debug mode')
@click.version_option(version=__version__)
@click.pass_context
def main(ctx, debug, user, password, config):

    try:
        params = cli.get_params(config)
        ctx.obj = params
    except Exception as e:
        print(e)
        sys.exit(1)

    if debug:
        params.debug = debug
    if user:
        params.email = user
    if password:
        params.password = password

main.add_command(cli.shell)
main.add_command(cli.list)
# main.add_command(cli.export)
# main.add_command(cli._import)
# main.add_command(cli.add)

if __name__ == "__main__":
    sys.exit(main())
