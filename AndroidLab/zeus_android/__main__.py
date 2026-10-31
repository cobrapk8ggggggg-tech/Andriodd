import os
import uvicorn
uvicorn.run("zeus_android.app:create_app", factory=True, host="0.0.0.0", port=int(os.environ.get("PORT", "8080")), access_log=False,
    ws_max_size=16384,ws_max_queue=4,ws_ping_interval=20,ws_ping_timeout=20)
