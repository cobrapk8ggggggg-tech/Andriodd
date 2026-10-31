"""A fixed ADB target. No caller-supplied shell, serial, URL or executable."""
import asyncio
import io
import os
import re
import signal
import xml.etree.ElementTree as ET


class Device:
    def __init__(self, serial, executable="adb"):
        if not re.fullmatch(r"[a-zA-Z0-9_.:-]{1,150}", serial): raise ValueError("Invalid configured ADB target")
        self.serial, self.executable = serial, executable

    def argv(self, *args): return [self.executable, "-s", self.serial, *map(str, args)]

    async def command(self, *args, timeout=20, limit=2_000_000):
        env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": os.environ.get("HOME", "/tmp"), "LANG": "C.UTF-8"}
        process = await asyncio.create_subprocess_exec(*self.argv(*args), stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE, env=env, start_new_session=True)
        async def collect(stream):
            data = bytearray()
            while block := await stream.read(65536):
                data.extend(block)
                if len(data) > limit: raise ValueError("Android output exceeds limit")
            return bytes(data)
        try:
            async with asyncio.timeout(timeout):
                out, error = await asyncio.gather(collect(process.stdout), collect(process.stderr))
                code = await process.wait()
            if code: raise ValueError("Android command failed: " + error.decode(errors="replace")[-500:])
            return out
        finally:
            if process.returncode is None:
                try: os.killpg(process.pid, signal.SIGKILL)
                except ProcessLookupError: pass
                await process.wait()

    async def connect(self):
        # `adb connect` is a host command and does not take -s.
        if ":" in self.serial:
            process = await asyncio.create_subprocess_exec(self.executable, "connect", self.serial,
                stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL)
            try: await asyncio.wait_for(process.wait(), 10)
            finally:
                if process.returncode is None: process.kill(); await process.wait()
        for attempt in range(60):
            try:
                if (await self.command("get-state",timeout=3)).strip() == b"device" and (await self.command("shell","getprop","sys.boot_completed",timeout=3)).strip()==b"1": break
            except (ValueError, OSError, asyncio.TimeoutError): pass
            if attempt == 59: raise ValueError("Android did not finish booting")
            await asyncio.sleep(1)
        await self.command("shell", "input", "keyevent", "224")
        await self.command('shell','wm','dismiss-keyguard')
        keyboard = os.environ.get("ZEUS_ANDROID_IME_APK", "/opt/zeus/ime.apk")
        if os.path.isfile(keyboard):
            await self.command("install", "-r", keyboard, timeout=60)
            for attempt in range(20):
                try:
                    await self.command("shell", "ime", "enable", "com.zeus.lab.ime/.LabIME");break
                except ValueError as error:
                    if 'Unknown input method' not in str(error) or attempt==19:raise
                    await asyncio.sleep(.5)
            await self.command("shell", "ime", "set", "com.zeus.lab.ime/.LabIME")
            await self.command("shell", "settings", "put", "secure", "show_ime_with_hard_keyboard", "1")

    async def size(self):
        text = (await self.command("shell", "wm", "size")).decode()
        matches = re.findall(r"(\d+)x(\d+)", text)
        if not matches: raise ValueError("Android display dimensions unavailable")
        return tuple(map(int, matches[-1]))

    async def action(self, operation, args):
        if operation == "tree":
            # External storage can still be mounting immediately after boot.
            # Never read a stale earlier hierarchy when uiautomator fails.
            path = "/data/local/tmp/zeus-window.xml"
            for attempt in range(3):
                await self.command("shell", "rm", "-f", path)
                await self.command("shell", "uiautomator", "dump", "--compressed", path, timeout=30)
                raw = await self.command("exec-out", "cat", path)
                try:
                    tree = ET.fromstring(raw)
                    if tree.tag != "hierarchy": raise ET.ParseError("Not an Android hierarchy")
                    break
                except ET.ParseError:
                    if attempt == 2: raise ValueError("Android has not produced a valid UI hierarchy; retry after the screen settles") from None
                    await asyncio.sleep(.5)
            nodes = []
            for node in tree.iter("node"):
                value = {k: v for k, v in node.attrib.items() if k in {"text", "resource-id", "class", "content-desc", "bounds", "clickable", "enabled", "password", "focused", "focusable"}}
                if value.get("password") == "true": value["text"] = "[password]"
                nodes.append(value)
                if len(nodes) >= 500: break
            return {"nodes": nodes}
        if operation in {"tap", "swipe"}:
            width, height = await self.size()
            def point(k, span):
                value = args.get(k)
                if isinstance(value, bool) or not isinstance(value, (int, float)) or not 0 <= value <= 1: raise ValueError("Coordinates must be between zero and one")
                return round(value * (span - 1))
            x, y = point("x", width), point("y", height)
            if operation == "tap": await self.command("shell", "input", "tap", x, y)
            else: await self.command("shell", "input", "swipe", x, y, point("x2", width), point("y2", height), 350)
        elif operation == "type":
            # ADB shell input cannot safely/reliably enter arbitrary Unicode.
            # Use the bundled IME's base64 broadcast; no text becomes shell code.
            import base64
            value = args.get("text", "")
            if not isinstance(value, str) or not 0 < len(value) <= 4000: raise ValueError("Text is empty or too long")
            selected=(await self.command("shell","settings","get","secure","default_input_method")).decode().strip()
            if selected!="com.zeus.lab.ime/.LabIME":
                # Android can restore its system IME after reboot/editor changes.
                # Selecting the lab IME is preparation; never retry text itself.
                await self.command("shell","ime","enable","com.zeus.lab.ime/.LabIME")
                await self.command("shell","ime","set","com.zeus.lab.ime/.LabIME")
            for attempt in range(25):
                ready=await self.command("shell","am","broadcast","-a","com.zeus.lab.READY","-p","com.zeus.lab.ime")
                if b"result=1" in ready: break
                if attempt==24: raise ValueError("اضغط حقل الكتابة وانتظر اتصال لوحة ZEUS بالمختبر قبل إرسال النص.")
                await asyncio.sleep(.15)
            encoded = base64.b64encode(value.encode()).decode()
            result = await self.command("shell", "am", "broadcast", "-a", "com.zeus.lab.INPUT", "-p", "com.zeus.lab.ime", "--es", "payload", encoded)
            if b"result=1" not in result: raise ValueError("تعذر تأكيد إدخال النص؛ افحص الحقل قبل إعادة الإرسال.")
        elif operation == "key":
            codes = {"back": "4", "home": "3", "recent": "187", "enter": "66", "delete": "67"}
            if args.get("key") not in codes: raise ValueError("Unsupported Android key")
            await self.command("shell", "input", "keyevent", codes[args["key"]])
        elif operation == "launch":
            package = args.get("package", "")
            if not isinstance(package, str) or not re.fullmatch(r"[a-zA-Z][a-zA-Z0-9_]*(?:\.[a-zA-Z0-9_]+)+", package): raise ValueError("Invalid Android package name")
            await self.command("shell", "monkey", "-p", package, "-c", "android.intent.category.LAUNCHER", "1")
        else: raise ValueError("Unknown Android operation")
        return {"executed": operation}

    async def screenshot(self):
        from PIL import Image
        raw = await self.command("exec-out", "screencap", "-p", limit=12_000_000)
        def convert():
            image = Image.open(io.BytesIO(raw)); image.thumbnail((1280, 1280))
            output = io.BytesIO(); image.convert("RGB").save(output, format="JPEG", quality=72)
            if output.tell() > 900_000: raise ValueError("Screenshot exceeds limit")
            return output.getvalue()
        return await asyncio.to_thread(convert)
