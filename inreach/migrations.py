# inreach/migrations.py
from mautrix.util.async_db import UpgradeTable, Scheme, Connection

upgrade_table = UpgradeTable()


@upgrade_table.register(description="Initial schema for InReach plugin")
async def upgrade_v1(conn: Connection, scheme: Scheme) -> None:
    # Rooms that use the InReach bridge.
    if scheme == Scheme.SQLITE:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS inreach_room (
                room_id     TEXT PRIMARY KEY,
                friendly    TEXT,
                created_by  TEXT,
                token_hash  TEXT,
                webhook_url TEXT,
                active      INTEGER NOT NULL DEFAULT 1,
                mode        TEXT NOT NULL DEFAULT 'manual',
                created_ts  BIGINT NOT NULL,
                updated_ts  BIGINT NOT NULL
            )
        """)
    else:
        await conn.execute("""
            CREATE TABLE IF NOT EXISTS inreach_room (
                room_id     TEXT PRIMARY KEY,
                friendly    TEXT,
                created_by  TEXT,
                token_hash  TEXT,
                webhook_url TEXT,
                active      BOOLEAN NOT NULL DEFAULT TRUE,
                mode        TEXT NOT NULL DEFAULT 'manual',
                created_ts  BIGINT NOT NULL,
                updated_ts  BIGINT NOT NULL
            )
        """)

    # Local mapping: Gmail +alias used by backend -> display label (“mari”)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS inreach_alias (
            room_id     TEXT NOT NULL,
            alias       TEXT NOT NULL,     -- full Gmail alias (e.g. mari-ab12cd34)
            label       TEXT NOT NULL,     -- short label shown in room (e.g. mari)
            created_ts  BIGINT NOT NULL,
            PRIMARY KEY (room_id, alias)
        )
    """)

    # Latest reply URL per room (overwritten whenever a new InReach mail is received)
    await conn.execute("""
        CREATE TABLE IF NOT EXISTS inreach_reply (
            room_id        TEXT PRIMARY KEY,
            last_reply_url TEXT,
            updated_ts     BIGINT
        )
    """)


@upgrade_table.register(description="Add helpful indexes")
async def upgrade_v2(conn: Connection, scheme: Scheme) -> None:
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_inreach_alias_room  ON inreach_alias (room_id)")
    await conn.execute("CREATE INDEX IF NOT EXISTS idx_inreach_alias_alias ON inreach_alias (alias)")


@upgrade_table.register(description="Safety: ensure nullable friendly and sane defaults")
async def upgrade_v3(conn: Connection, scheme: Scheme) -> None:
    # These ALTERs are defensive; they may no-op on fresh installs.
    try:
        await conn.execute("ALTER TABLE inreach_room ALTER COLUMN friendly DROP NOT NULL")
    except Exception:
        pass

    try:
        if scheme != Scheme.SQLITE:
            await conn.execute("ALTER TABLE inreach_room ALTER COLUMN active SET DEFAULT TRUE")
    except Exception:
        pass

    try:
        await conn.execute("ALTER TABLE inreach_room ALTER COLUMN mode SET DEFAULT 'manual'")
    except Exception:
        pass


@upgrade_table.register(description="Per-room policy: max_chars and relay_mode")
async def upgrade_v4(conn: Connection, scheme: Scheme) -> None:
    # Add two new columns with safe defaults.
    try:
        await conn.execute("ALTER TABLE inreach_room ADD COLUMN IF NOT EXISTS max_chars INTEGER")
    except Exception:
        pass
    try:
        # boolean default differs across engines; set explicit default values afterward
        if scheme == Scheme.SQLITE:
            await conn.execute("ALTER TABLE inreach_room ADD COLUMN IF NOT EXISTS relay_mode INTEGER")
        else:
            await conn.execute("ALTER TABLE inreach_room ADD COLUMN IF NOT EXISTS relay_mode BOOLEAN")
    except Exception:
        pass
    # Backfill sensible defaults where NULL
    try:
        await conn.execute("UPDATE inreach_room SET max_chars=160 WHERE max_chars IS NULL")
    except Exception:
        pass
    try:
        if scheme == Scheme.SQLITE:
            await conn.execute("UPDATE inreach_room SET relay_mode=0 WHERE relay_mode IS NULL")
        else:
            await conn.execute("UPDATE inreach_room SET relay_mode=FALSE WHERE relay_mode IS NULL")
    except Exception:
        pass


@upgrade_table.register(description="Add displayname and avatar_url columns to inreach_alias")
async def upgrade_v5(conn: Connection, scheme: Scheme) -> None:
    try:
        await conn.execute("ALTER TABLE inreach_alias ADD COLUMN IF NOT EXISTS displayname TEXT")
    except Exception:
        pass
    try:
        await conn.execute("ALTER TABLE inreach_alias ADD COLUMN IF NOT EXISTS avatar_url TEXT")
    except Exception:
        pass
    # backfill defaults
    try:
        await conn.execute(
            "UPDATE inreach_alias SET displayname=label WHERE displayname IS NULL OR displayname=''"
        )
    except Exception:
        pass
    try:
        await conn.execute("UPDATE inreach_alias SET avatar_url='' WHERE avatar_url IS NULL")
    except Exception:
        pass
