"""Live updates to every open browser tab over WebSocket."""

import asyncio
import json


class Events:
    def __init__(self):
        self.clients = set()
        self.loop = None

    def bind(self, loop):
        self.loop = loop

    async def send(self, msg):
        data = json.dumps(msg, default=str)
        dead = []
        for ws in list(self.clients):
            try:
                await ws.send_text(data)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.clients.discard(ws)

    def emit(self, msg):
        """Safe to call from any thread."""
        if self.loop is None:
            return
        try:
            running = asyncio.get_running_loop()
        except RuntimeError:
            running = None
        if running is self.loop:
            self.loop.create_task(self.send(msg))
        else:
            asyncio.run_coroutine_threadsafe(self.send(msg), self.loop)


events = Events()
