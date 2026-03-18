from datetime import UTC, datetime

from sqlmodel import Session

from backend.models import SystemTask


def _make_task(status="completed", task_type="scan", task_name="Scan nginx:latest"):
    return SystemTask(
        task_type=task_type,
        task_name=task_name,
        status=status,
        created_at=datetime.now(UTC),
    )


# ---------------------------------------------------------------------------
# GET /tasks
# Note: api_client starts the full app lifespan including the scheduler, which
# may insert SystemTask rows into test_db. Tests cannot assume the DB is empty.
# ---------------------------------------------------------------------------


def test_get_tasks_returns_list(api_client):
    client, _, _ = api_client
    response = client.get("/tasks")
    assert response.status_code == 200
    assert isinstance(response.json()["tasks"], list)


def test_get_tasks_includes_seeded_tasks(api_client):
    client, test_db, _ = api_client
    with Session(test_db.engine) as session:
        session.add(_make_task(status="completed", task_name="sentinel-completed"))
        session.add(_make_task(status="failed", task_name="sentinel-failed"))
        session.commit()

    tasks = client.get("/tasks").json()["tasks"]
    names = {t["task_name"] for t in tasks}
    assert "sentinel-completed" in names
    assert "sentinel-failed" in names


def test_get_tasks_limit_respected(api_client):
    client, test_db, _ = api_client
    with Session(test_db.engine) as session:
        for i in range(20):
            session.add(_make_task(task_name=f"bulk-task-{i}"))
        session.commit()

    response = client.get("/tasks?page_size=5")
    assert response.status_code == 200
    assert len(response.json()["tasks"]) <= 5


def test_get_tasks_timestamps_serialised(api_client):
    client, test_db, _ = api_client
    with Session(test_db.engine) as session:
        task = _make_task(task_name="ts-sentinel")
        task.started_at = datetime.now(UTC)
        task.finished_at = datetime.now(UTC)
        session.add(task)
        session.commit()

    tasks = client.get("/tasks").json()["tasks"]
    sentinel = next(t for t in tasks if t["task_name"] == "ts-sentinel")
    assert sentinel["created_at"] is not None
    assert sentinel["started_at"] is not None
    assert sentinel["finished_at"] is not None


# ---------------------------------------------------------------------------
# GET /tasks/scheduled
# The api_client fixture starts the full app lifespan so the scheduler IS active.
# ---------------------------------------------------------------------------


def test_get_scheduled_tasks_returns_jobs(api_client):
    client, _, _ = api_client
    response = client.get("/tasks/scheduled")
    assert response.status_code == 200
    data = response.json()
    assert "jobs" in data
    # Scheduler is active during the test client lifespan
    assert isinstance(data["jobs"], list)
    assert len(data["jobs"]) > 0
