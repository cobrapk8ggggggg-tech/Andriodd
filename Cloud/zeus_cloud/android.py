"""Optional remote Android worker. Never install Android or forward ADB on Railway."""
import base64
import hashlib
import hmac
import json
import os
import time
from urllib.parse import urlsplit
import httpx


ANDROID_NAMES = {"android_device", "android_ui", "android_screenshot", "android_network", "android_project"}


class AndroidGateway:
    def __init__(self, url=None, key=None, public_url=None, client=None):
        self.url = (url if url is not None else os.environ.get("ZEUS_ANDROID_WORKER_URL", "")).rstrip("/")
        self.key = key if key is not None else os.environ.get("ZEUS_ANDROID_SIGNING_KEY", "")
        self.public_url = (public_url if public_url is not None else os.environ.get("ZEUS_ANDROID_PUBLIC_URL", self.url)).rstrip("/")
        self.client = client or httpx.AsyncClient(timeout=45, follow_redirects=False)
        for address in [self.url, self.public_url]:
            if address:
                value = urlsplit(address)
                if value.scheme != "https" or not value.hostname or value.username or value.password or value.query or value.fragment: raise ValueError("Android worker requires a configured HTTPS origin")

    @property
    def configured(self): return bool(self.url and self.public_url and len(self.key) >= 32)

    def token(self, owner, conversation, role):
        if not self.configured: raise ValueError("مختبر Android غير موصول بخادم بعد؛ لم يُشغّل جهاز أو يُثبّت شيء محليًا.")
        raw = json.dumps({"sub": owner, "conversation": conversation, "role": role, "exp": int(time.time())+300}, separators=(",", ":")).encode()
        payload = base64.urlsafe_b64encode(raw).rstrip(b"=").decode()
        return payload + "." + hmac.new(self.key.encode(), payload.encode(), hashlib.sha256).hexdigest()

    def access(self, owner, conversation):
        return {"url": self.public_url + "/lab/", "token": self.token(owner, conversation, "viewer"), "expires_in": 300}

    async def take(self,owner,conversation):
        response=await self.client.post(self.url+'/v1/control/take',headers={'Authorization':'Bearer '+self.token(owner,conversation,'viewer')})
        if response.status_code!=200:raise ValueError('تعذر تأكيد استعادة التحكم في Android')
        return response.json()

    async def approve_changes(self,owner,conversation,project):
        response=await self.client.post(self.url+'/v1/tool',headers={'Authorization':'Bearer '+self.token(owner,conversation,'viewer')},
            json={'name':'android_project','arguments':{'operation':'approve_changes','project':project},'request_id':'consent-'+str(__import__('uuid').uuid4())})
        if response.status_code!=200:raise ValueError('تعذر تسجيل موافقة تعديل نسخة الاختبار')
        return response.json()

    async def tool(self, owner, conversation, name, args, request_id):
        if name not in ANDROID_NAMES: raise ValueError("Unknown Android tool")
        token = self.token(owner, conversation, "agent")
        args = {k:v for k,v in args.items() if k not in {"tool_title", "approval_reason"}}
        try:
            async with self.client.stream("POST", self.url + "/v1/tool", headers={"Authorization": "Bearer " + token},
                json={"name":name, "arguments":args, "request_id":request_id}) as response:
                content = bytearray()
                async for block in response.aiter_bytes():
                    content.extend(block)
                    if len(content) > 1_400_000: raise ValueError("Android worker response exceeds limit")
                if response.status_code != 200:
                    raise ValueError("تعذّر إجراء Android؛ الجهاز مشغول أو متوقف، أو انتهت صلاحية الوصول. راجع المختبر.")
                result=json.loads(content)
                if name=="android_screenshot":
                    try:
                        image=result["image"];raw=base64.b64decode(image["data"],validate=True)
                        if image["mime"]!="image/jpeg" or len(raw)>900000 or not raw.startswith(b"\xff\xd8"): raise ValueError()
                    except (KeyError,TypeError,ValueError): raise ValueError("Invalid Android screenshot response") from None
                return result
        except httpx.HTTPError:
            raise ValueError("خادم Android غير متاح؛ لم يُحوّل التنفيذ إلى الجهاز المحلي ولم تُكرر العملية.") from None

    async def close(self): await self.client.aclose()

    async def delete(self, owner, conversation):
        if not self.configured: return
        try:
            response=await self.client.delete(self.url+"/v1/session",headers={"Authorization":"Bearer "+self.token(owner,conversation,"agent")})
            if response.status_code!=200 or response.json().get("deleted") is not True: raise ValueError("تعذر تأكيد حذف ملفات مختبر Android؛ أعد المحاولة.")
        except httpx.HTTPError: raise ValueError("خادم Android غير متاح لتأكيد الحذف؛ لن يُعلن حذف بياناته.") from None
