import asyncio
import signal


def add_signal_handlers():
    """
    Properly handles SIGINT and SIGTERM signals. Ensures correct end of all coroutines.
    :return:
    """
    loop = asyncio.get_event_loop()

    async def shutdown(_: signal.Signals) -> None:
        """
        Cancel all running async tasks (other than this one) when called.
        By catching asyncio.CancelledError, any running task can perform
        any necessary cleanup when it's cancelled.
        """
        for task in asyncio.all_tasks(loop):
            if task is not asyncio.current_task(loop):
                task.cancel()

    for sig in [signal.SIGINT, signal.SIGTERM]:
        loop.add_signal_handler(sig, lambda: asyncio.create_task(shutdown(sig)))