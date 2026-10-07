from django.db import migrations

# TextField columns can't take a plain index on MariaDB and Django has no
# prefix-index syntax, so this is raw SQL, deliberately absent from model state.
# Exact-match lookups (get_or_create(value=...)) use the prefix; InnoDB rechecks
# the full value. Other backends (the SQLite test DB) skip it.
TABLE, COL, IDX = "email_process_mailaddress", "address", "mailaddr_address_prefix_idx"


def add_index(apps, schema_editor):
    if schema_editor.connection.vendor == "mysql":
        schema_editor.execute(
            f"CREATE INDEX {IDX} ON {TABLE} ({COL}(255)) ALGORITHM=INPLACE LOCK=NONE"
        )


def drop_index(apps, schema_editor):
    if schema_editor.connection.vendor == "mysql":
        schema_editor.execute(f"DROP INDEX {IDX} ON {TABLE}")


class Migration(migrations.Migration):
    atomic = False  # MariaDB DDL is non-transactional
    dependencies = [("email_process", "0002_mailaddress_ioc_confidence_mailaddress_ioc_level_and_more")]
    operations = [migrations.RunPython(add_index, drop_index)]
