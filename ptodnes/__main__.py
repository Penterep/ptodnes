import sys
import asyncio
from ptodnes.ptodnes import main


def __main__():
    if sys.platform == 'win32':
        asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(main(loop))
    finally:
        loop.close()


if __name__ == "__main__":
    __main__()
