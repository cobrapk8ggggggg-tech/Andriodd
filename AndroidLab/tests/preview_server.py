"""UI inspection only: no simulated Android device and no production credentials."""
import os
import tempfile
import uvicorn
from zeus_android.app import create_app
from zeus_android.tokens import decode

if __name__ == "__main__":
    with tempfile.TemporaryDirectory() as directory:
        app=create_app(root=directory,key=os.environ['LAB_TEST_KEY'],owner='ui-test')
        scope=app.state.lab.scope(decode(os.environ['LAB_TEST_KEY'],os.environ['LAB_TEST_TOKEN']))
        app.state.lab.capture(scope,{'flow_id':'saved','sequence':1,'phase':'complete','method':'POST','url':'https://saved.invalid/past','status':200,'response_body':{'base64':'c2F2ZWQgbG9n','available':True,'truncated':False,'bytes':9}})
        uvicorn.run(app,host='127.0.0.1',port=8769,access_log=False,log_level='warning')
