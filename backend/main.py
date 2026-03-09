import colorlog
import logging
import time
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI

from .database import db
from .scheduler import ContainerScheduler

from .routers import vulnerabilities, containers, tasks, settings, internal

logger = logging.getLogger(__name__)

@asynccontextmanager
async def lifespan(_: FastAPI):
    t_start = time.perf_counter()
    logger.info("Startup: beginning lifespan init")

    db.init()
    logger.info("Startup: db.init() done (%.2fs)", time.perf_counter() - t_start)

    colorlog.basicConfig(
        level=colorlog.INFO,
        format="%(asctime)s %(log_color)s%(levelname)-8s%(reset)s %(name)s - %(message)s",
        force=True,
    )

    scheduler = ContainerScheduler(db)
    logger.info("Startup: ContainerScheduler created (%.2fs)", time.perf_counter() - t_start)

    scheduler.start()
    logger.info("Startup: scheduler started — ready in %.2fs total", time.perf_counter() - t_start)
    yield
    scheduler.shutdown()

app = FastAPI(lifespan=lifespan)
# Fastapi router attribute usually aliased so it matches earlier imports if needed.
router = app.router

# Mount all our new routers
app.include_router(vulnerabilities.router)
app.include_router(containers.router)
app.include_router(tasks.router)
app.include_router(settings.router)
app.include_router(internal.router)


_APP_VERSION = (Path(__file__).resolve().parent.parent / "VERSION").read_text().strip()

@app.get("/version")
def get_version():
    return {"version": _APP_VERSION}

