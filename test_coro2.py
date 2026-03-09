import asyncio
from unittest.mock import patch, AsyncMock

async def scan():
    pass

def do_work():
    asyncio.create_task(scan())

@patch("__main__.scan", new_callable=AsyncMock)
def test_foo(mock_scan):
    mock_scan.return_value = None # No, wait, AsyncMock called returns a coroutine mock
    do_work()

if __name__ == "__main__":
    try:
        test_foo()
        print("Done")
    except Exception as e:
        print(f"Error: {e}")
