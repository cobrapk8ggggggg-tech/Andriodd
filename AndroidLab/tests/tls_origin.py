"""Controlled HTTPS origin and system-CA provisioning for a disposable AVD only."""
import datetime
import asyncio
import ipaddress
import json
from pathlib import Path
import ssl
import subprocess
import threading
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from cryptography import x509
from cryptography.hazmat.primitives import hashes,serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID,ExtendedKeyUsageOID


def start_origin(directory, hold=False):
    root=Path(directory);now=datetime.datetime.now(datetime.timezone.utc)
    ca_key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    ca_name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'ZEUS CI Origin CA')])
    ca=x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name).public_key(ca_key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=True,path_length=0),critical=True).add_extension(x509.KeyUsage(True,False,False,False,False,True,True,False,False),critical=True).add_extension(x509.SubjectKeyIdentifier.from_public_key(ca_key.public_key()),critical=False).sign(ca_key,hashes.SHA256())
    key=rsa.generate_private_key(public_exponent=65537,key_size=2048)
    leaf=x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'zeus-probe.invalid')])).issuer_name(ca_name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.BasicConstraints(ca=False,path_length=None),critical=True).add_extension(x509.SubjectAlternativeName([x509.DNSName('zeus-probe.invalid'),x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]),critical=False).add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),critical=False).add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),critical=False).sign(ca_key,hashes.SHA256())
    public=root/'origin-ca.pem';public.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    certificate=root/'origin.pem';certificate.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
    private=root/'origin.key';private.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()));private.chmod(0o600)
    class Origin(BaseHTTPRequestHandler):
        def log_message(self,*args):pass
        def do_POST(self):
            data=self.rfile.read(min(8000,int(self.headers.get('Content-Length','0'))))
            self.server.received.set()
            if hold: self.server.release.wait(30)
            self.send_response(200);self.send_header('Content-Type','application/json');self.end_headers();self.wfile.write(json.dumps({'received':data.decode()}).encode())
            self.server.replied.set()
    server=ThreadingHTTPServer(('127.0.0.1',8091),Origin)
    server.received=threading.Event();server.release=threading.Event();server.replied=threading.Event()
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(certificate,private)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    threading.Thread(target=server.serve_forever,daemon=True).start()
    return server,public


async def install_interception_ca(device,certificate,log_path=None):
    # This helper is never copied into the production Android image. API29
    # userdebug+writable-system is chosen explicitly for this acceptance test.
    digest=subprocess.check_output(['openssl','x509','-in',str(certificate),'-subject_hash_old','-noout'],text=True).strip()
    assert len(digest)==8 and all(c in '0123456789abcdef' for c in digest)
    log=[]
    async def step(*args,**kwargs):
        output=await device.command(*args,**kwargs);log.append(' '.join(args)+'\n'+output.decode(errors='replace'));return output
    try:
        await step('root');await step('wait-for-device',timeout=30)
        try:await step('shell','avbctl','disable-verification')
        except ValueError as error:
            if 'not found' not in str(error):raise
        await step('disable-verity')
        await step('reboot');await step('wait-for-device',timeout=60)
        for attempt in range(90):
            try:
                if (await device.command('shell','getprop','sys.boot_completed',timeout=3)).strip()==b'1':break
            except (ValueError,asyncio.TimeoutError):pass
            if attempt==89:raise AssertionError('Disposable AVD did not reboot for CA provisioning')
            await asyncio.sleep(1)
        await step('root');await step('wait-for-device',timeout=30);await step('remount',timeout=30)
        destination='/system/etc/security/cacerts/'+digest+'.0'
        await step('push',str(certificate),destination,timeout=30);await step('shell','chmod','644',destination)
        await step('reboot');await step('wait-for-device',timeout=60)
        for attempt in range(90):
            try:
                if (await device.command('shell','getprop','sys.boot_completed',timeout=3)).strip()==b'1':break
            except (ValueError,asyncio.TimeoutError):pass
            if attempt==89:raise AssertionError('AVD did not reload the provisioned CA store')
            await asyncio.sleep(1)
        await step('shell','input','keyevent','224')
    finally:
        if log_path:Path(log_path).write_text('\n'.join(log))
