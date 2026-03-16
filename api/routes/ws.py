import asyncio
import json
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from api.database import get_recent_scans

router  = APIRouter()
clients = set()

async def broadcast(message: dict):
    dead = set()
    for ws in clients:
        try:
            await ws.send_text(json.dumps(message))
        except:
            dead.add(ws)
    clients.difference_update(dead)

def get_connection_manager():
    return _ConnectionManager()

class _ConnectionManager:
    async def send_progress(self, scan_id, progress, status, message):
        await broadcast({
            "type": "progress", "scan_id": scan_id,
            "progress": progress, "status": status,
            "message": message
        })
    async def send_finding(self, scan_id, finding):
        await broadcast({"type": "finding",
                         "scan_id": scan_id, "finding": finding})
    async def send_complete(self, scan_id, summary):
        await broadcast({"type": "complete",
                         "scan_id": scan_id, "summary": summary})

@router.websocket("/ws/alerts")
async def ws_alerts(websocket: WebSocket):
    await websocket.accept()
    clients.add(websocket)
    try:
        recent = await get_recent_scans(5)
        await websocket.send_text(json.dumps(
            {"type": "history", "data": recent}
        ))
        while True:
            await asyncio.sleep(30)
            await websocket.send_text(json.dumps({"type": "ping"}))
    except WebSocketDisconnect:
        clients.discard(websocket)