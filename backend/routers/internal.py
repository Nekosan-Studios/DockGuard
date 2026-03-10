from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import text as sa_text
from sqlmodel import Session

from ..database import db

router = APIRouter(prefix="/db", tags=["Internal"])

@router.get("/tables")
def get_db_tables(session: Session = Depends(db.get_session)):
    """List application database tables (excludes alembic internals)."""
    rows = session.execute(
        sa_text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'alembic%' ORDER BY name")
    ).fetchall()
    return {"tables": [r[0] for r in rows]}


@router.get("/table/{table_name}")
def get_db_table_rows(
    table_name: str,
    limit: int = Query(default=100, le=100),
    session: Session = Depends(db.get_session),
):
    """Return up to `limit` rows from a table (read-only)."""
    valid_tables = {
        r[0] for r in session.execute(
            sa_text("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'alembic%'")
        ).fetchall()
    }
    if table_name not in valid_tables:
        raise HTTPException(status_code=404, detail=f"Table '{table_name}' not found")

    col_rows = session.execute(sa_text(f'PRAGMA table_info("{table_name}")')).fetchall()
    columns = [r[1] for r in col_rows]

    rows = session.execute(
        sa_text(f'SELECT * FROM "{table_name}" LIMIT :limit'),
        {"limit": limit},
    ).fetchall()

    return {
        "table": table_name,
        "columns": columns,
        "rows": [dict(zip(columns, row)) for row in rows],
        "count": len(rows),
    }
