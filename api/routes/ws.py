"""
WebSocket Routes - Real-time communication for scan progress
"""
from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from typing import Dict, Set
import json
import asyncio

router = APIRouter()


class ConnectionManager:
    """Manage WebSocket connections"""

    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, scan_id: str):
        await websocket.accept()
        if scan_id not in self.active_connections:
            self.active_connections[scan_id] = set()
        self.active_connections[scan_id].add(websocket)

    def disconnect(self, websocket: WebSocket, scan_id: str):
        if scan_id in self.active_connections:
            self.active_connections[scan_id].discard(websocket)
            if not self.active_connections[scan_id]:
                del self.active_connections[scan_id]

    async def broadcast_to_scan(self, scan_id: str, message: dict):
        if scan_id in self.active_connections:
            for connection in self.active_connections[scan_id]:
                try:
                    await connection.send_json(message)
                except Exception:
                    pass

    async def send_progress(self, scan_id: str, progress: int, stage: str, message: str):
        await self.broadcast_to_scan(scan_id, {
            "type": "progress",
            "scan_id": scan_id,
            "progress": progress,
            "stage": stage,
            "message": message
        })

    async def send_finding(self, scan_id: str, finding: dict):
        await self.broadcast_to_scan(scan_id, {
            "type": "finding",
            "scan_id": scan_id,
            "finding": finding
        })

    async def send_complete(self, scan_id: str, summary: dict):
        await self.broadcast_to_scan(scan_id, {
            "type": "complete",
            "scan_id": scan_id,
            "summary": summary
        })


manager = ConnectionManager()


@router.websocket("/scan/{scan_id}")
async def websocket_scan(websocket: WebSocket, scan_id: str):
    """WebSocket endpoint for scan progress updates"""
    await manager.connect(websocket, scan_id)
    try:
        while True:
            data = await websocket.receive_text()
            message = json.loads(data)

            if message.get("type") == "ping":
                await websocket.send_json({"type": "pong"})
    except WebSocketDisconnect:
        manager.disconnect(websocket, scan_id)


def get_connection_manager() -> ConnectionManager:
    """Get the global connection manager instance"""
    return manager


async def broadcast(message: dict):
    """Broadcast a message to all active scan connections"""
    for scan_id in list(manager.active_connections.keys()):
        await manager.broadcast_to_scan(scan_id, message)
