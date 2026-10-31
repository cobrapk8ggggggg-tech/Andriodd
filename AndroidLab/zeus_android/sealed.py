"""Client-key sealed envelopes. Public Actions artifacts contain no access keys."""
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import uuid
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey,X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

MAGIC=b'ZLAB1\n'
CHUNK=1024*1024

def b64(raw):return base64.b64encode(raw).decode()
def unb64(value):return base64.b64decode(value,validate=True)
def context(session):return str(uuid.UUID(session)).encode()
def derive(secret,session):return HKDF(algorithm=hashes.SHA256(),length=32,salt=context(session),info=b'ZEUS Android Lab envelope v1').derive(secret)

def seal(data,public_key,session):
    ephemeral=X25519PrivateKey.generate();public=X25519PublicKey.from_public_bytes(unb64(public_key))
    key=derive(ephemeral.exchange(public),session);nonce=os.urandom(12)
    return {'version':1,'session':str(uuid.UUID(session)),
        'ephemeral_public_key':b64(ephemeral.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw)),
        'nonce':b64(nonce),'ciphertext':b64(AESGCM(key).encrypt(nonce,data,b'zeus-lab.v1:'+context(session)))}

def open_envelope(value,private_key):
    if value.get('version')!=1:raise ValueError('Unknown laboratory envelope version')
    secret=X25519PrivateKey.from_private_bytes(private_key).exchange(X25519PublicKey.from_public_bytes(unb64(value['ephemeral_public_key'])))
    key=derive(secret,value['session'])
    return AESGCM(key).decrypt(unb64(value['nonce']),unb64(value['ciphertext']),b'zeus-lab.v1:'+context(value['session']))

def seal_file(source,target,public_key,session,maximum=200*1024*1024):
    source,target=Path(source),Path(target);size=source.stat().st_size
    if size>maximum:raise ValueError('Checkpoint exceeds encrypted archive budget')
    ephemeral=X25519PrivateKey.generate();public=X25519PublicKey.from_public_bytes(unb64(public_key));key=derive(ephemeral.exchange(public),session);prefix=os.urandom(8)
    header={'version':1,'session':str(uuid.UUID(session)),'plaintext_bytes':size,'chunk_bytes':CHUNK,'nonce_prefix':b64(prefix),
        'ephemeral_public_key':b64(ephemeral.public_key().public_bytes(serialization.Encoding.Raw,serialization.PublicFormat.Raw))}
    raw=json.dumps(header,separators=(',',':'),sort_keys=True).encode();aad=hashlib.sha256(raw).digest();cipher=AESGCM(key)
    digest=hashlib.sha256();counter=0;total=0;created=False
    try:
        with source.open('rb') as original,target.open('xb') as output:
            created=True
            output.write(MAGIC+struct.pack('>I',len(raw))+raw)
            while block:=original.read(CHUNK):
                total+=len(block)
                if total>size:raise ValueError('Checkpoint changed during encryption')
                digest.update(block);number=struct.pack('>I',counter);encrypted=cipher.encrypt(prefix+number,block,aad+number)
                output.write(struct.pack('>I',len(encrypted))+encrypted);counter+=1
            if total!=size:raise ValueError('Checkpoint changed during encryption')
            number=struct.pack('>I',counter);output.write(struct.pack('>I',0)+cipher.encrypt(prefix+number,b'',aad+number+b'end'))
        return {'bytes':size,'sha256':digest.hexdigest(),'encrypted_bytes':target.stat().st_size,'chunks':counter,'session':header['session']}
    except BaseException:
        if created:target.unlink(missing_ok=True)
        raise

def open_file(source,target,private_key,maximum=200*1024*1024):
    source,target=Path(source),Path(target)
    created=False
    def read(file,size):
        data=file.read(size)
        if len(data)!=size:raise ValueError('Truncated encrypted checkpoint')
        return data
    try:
        with source.open('rb') as file:
            if read(file,len(MAGIC))!=MAGIC:raise ValueError('Invalid checkpoint format')
            length=struct.unpack('>I',read(file,4))[0]
            if length>4096:raise ValueError('Checkpoint header exceeds limit')
            raw=read(file,length);header=json.loads(raw)
            if header.get('version')!=1 or header.get('chunk_bytes')!=CHUNK or not 0<=header.get('plaintext_bytes',-1)<=maximum:raise ValueError('Invalid checkpoint limits')
            secret=X25519PrivateKey.from_private_bytes(private_key).exchange(X25519PublicKey.from_public_bytes(unb64(header['ephemeral_public_key'])))
            cipher=AESGCM(derive(secret,header['session']));prefix=unb64(header['nonce_prefix']);aad=hashlib.sha256(raw).digest();counter=0;total=0
            if len(prefix)!=8:raise ValueError('Invalid checkpoint nonce')
            with target.open('xb') as output:
                created=True
                while True:
                    length=struct.unpack('>I',read(file,4))[0];number=struct.pack('>I',counter)
                    if not length:
                        cipher.decrypt(prefix+number,read(file,16),aad+number+b'end')
                        if file.read(1) or total!=header['plaintext_bytes']:raise ValueError('Incomplete checkpoint contents')
                        return header
                    if not 16<length<=CHUNK+16:raise ValueError('Invalid checkpoint frame')
                    block=cipher.decrypt(prefix+number,read(file,length),aad+number);total+=len(block)
                    if total>header['plaintext_bytes']:raise ValueError('Checkpoint exceeds declared length')
                    output.write(block);counter+=1
    except BaseException:
        if created:target.unlink(missing_ok=True)
        raise
