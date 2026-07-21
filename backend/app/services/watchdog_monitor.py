import os
import time
import asyncio
from typing import Optional
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
from backend.app.utils.log_parsers import parse_log_file
from backend.app.detectors.engine import run_detection
from backend.app.database.session import SessionLocal
from backend.app.models.alert import Alert
from backend.app.models.log import Log
from backend.app.services.notifications import dispatch_alert_notifications
from backend.app.websocket.manager import ws_manager

MONITOR_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))), "logs")
os.makedirs(MONITOR_DIR, exist_ok=True)

class LogFileHandler(FileSystemEventHandler):
    def __init__(self, loop: asyncio.AbstractEventLoop):
        super().__init__()
        self.loop = loop
        self.processed_files = set()

    def process_file(self, filepath: str):
        if not os.path.isfile(filepath):
            return

        filename = os.path.basename(filepath)
        log_type = "auth" if "auth" in filename.lower() else "syslog" if "sys" in filename.lower() else "generic"

        events = parse_log_file(filepath, log_type)
        if not events:
            return

        alerts = run_detection(events)

        db = SessionLocal()
        try:
            saved_count = 0
            for ev in events:
                new_log = Log(
                    filename=filename,
                    event_type=ev.get("event_type", "INFO"),
                    raw_log=ev.get("raw", ""),
                    timestamp=ev.get("timestamp", "")
                )
                db.add(new_log)

            for a in alerts:
                existing = db.query(Alert).filter(
                    Alert.attack_type == a.get("attack_type"),
                    Alert.source_ip == a.get("source_ip"),
                    Alert.timestamp == a.get("timestamp")
                ).first()

                if not existing:
                    new_alert = Alert(
                        timestamp=a.get("timestamp"),
                        source_ip=a.get("source_ip"),
                        destination_ip=a.get("destination_ip"),
                        severity=a.get("severity"),
                        attack_type=a.get("attack_type"),
                        description=a.get("description"),
                        log_source=a.get("log_source"),
                        status="OPEN",
                        mitre_technique_id=a.get("mitre_technique_id"),
                        mitre_technique_name=a.get("mitre_technique_name"),
                        mitre_tactic=a.get("mitre_tactic"),
                        recommendation=a.get("recommendation"),
                        raw_log=a.get("raw_log")
                    )
                    db.add(new_alert)
                    saved_count += 1
            db.commit()

            if alerts:
                dispatch_alert_notifications(alerts)
                if self.loop and self.loop.is_running():
                    asyncio.run_coroutine_threadsafe(
                        ws_manager.broadcast({"type": "NEW_ALERTS", "count": len(alerts), "alerts": alerts[:5]}),
                        self.loop
                    )
            print(f"[WATCHDOG] Processed '{filename}': {len(events)} events, {saved_count} new alerts.")
        except Exception as exc:
            db.rollback()
            print(f"[WATCHDOG] Error processing {filepath}: {exc}")
        finally:
            db.close()

    def on_created(self, event):
        if not event.is_directory:
            time.sleep(0.2)
            self.process_file(event.src_path)

    def on_modified(self, event):
        if not event.is_directory:
            time.sleep(0.2)
            self.process_file(event.src_path)


class RealtimeMonitorService:
    def __init__(self):
        self.observer: Optional[Observer] = None
        self.is_running: bool = False

    def start(self, loop: asyncio.AbstractEventLoop = None):
        if self.is_running:
            return True
        try:
            event_handler = LogFileHandler(loop or asyncio.get_event_loop())
            self.observer = Observer()
            self.observer.schedule(event_handler, path=MONITOR_DIR, recursive=False)
            self.observer.start()
            self.is_running = True
            print(f"[MONITOR] Real-time Log Monitor started watching: {MONITOR_DIR}")
            return True
        except Exception as exc:
            print(f"[MONITOR] Failed to start log monitor: {exc}")
            return False

    def stop(self):
        if not self.is_running or not self.observer:
            return True
        try:
            self.observer.stop()
            self.observer.join()
            self.is_running = False
            print("[MONITOR] Real-time Log Monitor stopped.")
            return True
        except Exception as exc:
            print(f"[MONITOR] Failed to stop monitor: {exc}")
            return False

monitor_service = RealtimeMonitorService()
