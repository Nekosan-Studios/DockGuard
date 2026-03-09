import asyncio
from unittest.mock import patch, MagicMock

async def scan():
    pass

def do_work():
    asyncio.create_task(scan())

@patch("test_coro.asyncio.create_task")
def test_foo(mock_create):
    do_work()

if __name__ == "__main__":
    test_foo()
    print("Done")
