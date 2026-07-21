import asyncio
from fastapi import APIRouter
from backend.app.services.watchdog_monitor import monitor_service

router = APIRouter(prefix="/monitor", tags=["Monitoring"])

@router.get("/status")
def get_monitor_status():
    return {
        "active": monitor_service.is_running,
        "monitored_directory": "logs/"
    }

@router.post("/start")
def start_monitor():
    loop = asyncio.get_event_loop()
    success = monitor_service.start(loop=loop)
    return {
        "status": "ok" if success else "error",
        "active": monitor_service.is_running,
        "message": "Real-time log directory monitor started." if success else "Failed to start monitor."
    }

@router.post("/stop")
def stop_monitor():
    success = monitor_service.stop()
    return {
        "status": "ok" if success else "error",
        "active": monitor_service.is_running,
        "message": "Real-time log directory monitor stopped." if success else "Failed to stop monitor."
    }
