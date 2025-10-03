import click
from update_server import create_app, db
from update_server.models import seed_demo
from flask_migrate import upgrade, migrate, init, stamp

app = create_app()

@app.shell_context_processor
def ctx():
    from update_server import models
    return {"db": db, "models": models}

@click.group()
def cli():
    pass

@cli.command("db-init")
def db_init():
    with app.app_context():
        try:
            init()
        except Exception:
            pass
        stamp()
        migrate()
        upgrade()
        click.echo("DB initialized & upgraded.")

@cli.command("seed")
def seed():
    with app.app_context():
        seed_demo()
        click.echo("Demo data seeded.")

if __name__ == "__main__":
    cli()
