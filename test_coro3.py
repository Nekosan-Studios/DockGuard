import asyncio
from unittest.mock import patch

async def scan():
    pass

def do_work():
    asyncio.create_task(scan())

async def dummy_coro(*args, **kwargs):
    pass

@patch("__main__.scan", side_effect=dummy_coro)
@patch("__main__.asyncio.create_task")
def test_foo(mock_create_task, mock_scan):
    do_work()
    mock_scan.assert_called_once()
    mock_create_task.assert_called_once()

if __name__ == "__main__":
    test_foo()
    print("Done")
