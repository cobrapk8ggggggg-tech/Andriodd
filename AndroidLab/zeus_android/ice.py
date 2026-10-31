"""Short-lived coturn REST credentials for both ends of the WebRTC connection."""
import base64
import hashlib
import hmac
import os
import time


def servers(identity, now=None):
    result=[]
    stun=os.environ.get("ZEUS_ANDROID_STUN_URL", "")
    if stun:
        if not stun.startswith("stun:"): raise ValueError("Invalid configured STUN URL")
        result.append({"urls":stun})
    turn=os.environ.get("ZEUS_ANDROID_TURN_URL", "")
    if turn:
        secret=os.environ.get("ZEUS_ANDROID_TURN_SECRET", "")
        if not turn.startswith(("turn:","turns:")) or len(secret)<32: raise ValueError("Configure the TURN REST shared secret before opening video")
        username=str(int(now or time.time())+300)+":"+hashlib.sha256(identity.encode()).hexdigest()[:16]
        password=base64.b64encode(hmac.new(secret.encode(),username.encode(),hashlib.sha1).digest()).decode()
        result.append({"urls":turn,"username":username,"credential":password})
    return result
