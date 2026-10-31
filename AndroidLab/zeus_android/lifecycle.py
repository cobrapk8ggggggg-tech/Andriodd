import os
import httpx


class Lifecycle:
    async def action(self, operation):
        url=os.environ.get("ZEUS_ANDROID_NODE_URL", "")
        if not url:
            if os.environ.get("ZEUS_ANDROID_EXTERNAL_AVD") == "1": return
            raise ValueError("Configure the Android container controller before starting a device")
        key=os.environ.get("ZEUS_ANDROID_NODE_TOKEN", "")
        if operation not in {"start","stop","reset"} or len(key)<32: raise ValueError("Invalid Android container controller configuration")
        try:
            async with httpx.AsyncClient(timeout=35,follow_redirects=False,trust_env=False) as client:
                response=await client.post(url.rstrip("/")+"/"+operation,headers={"Authorization":"Bearer "+key})
                if response.status_code!=200 or response.json().get("ok") is not True: raise ValueError("Android container did not confirm "+operation)
        except httpx.HTTPError: raise ValueError("Android container controller is unavailable") from None
