#!/usr/bin/env python3
"""Testes de contrato e segurança do proxy UI. Backend HTTP simulado; banco real intacto."""
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

ROOT = Path(__file__).resolve().parent.parent


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


class FakeRust(BaseHTTPRequestHandler):
    def log_message(self, *_): pass
    def dispatch(self):
        size=int(self.headers.get('Content-Length','0'))
        payload=self.rfile.read(size)
        FakeRust.received.append((self.command,self.path,payload,self.headers.get('X-Lab-Token')))
        if self.command=='POST':
            self.send_response(201)
            self.send_header('Location','/api/v1/users/1')
            content=b'{"data":{"id":1,"name":"Ana Silva","email":"ana@example.com"}}'
        elif self.command=='DELETE':
            self.send_response(204)
            content=b''
        else:
            self.send_response(200)
            content=b'{"data":[],"pagination":{"total":0,"limit":20,"offset":0}}'
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',str(len(content)))
        self.end_headers()
        self.wfile.write(content)
    def do_GET(self): self.dispatch()
    def do_POST(self): self.dispatch()
    def do_PUT(self): self.dispatch()
    def do_PATCH(self): self.dispatch()
    def do_DELETE(self): self.dispatch()


class UI54Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp=tempfile.TemporaryDirectory(prefix='fase54_test_')
        cls.root=Path(cls.temp.name)
        (cls.root/'docs/ui').mkdir(parents=True)
        (cls.root/'scripts').mkdir()
        for file in (ROOT/'docs/ui').iterdir():
            shutil.copy2(file, cls.root/'docs/ui'/file.name)
        if (ROOT/'docs/openapi.json').is_file():
            shutil.copy2(ROOT/'docs/openapi.json',cls.root/'docs/openapi.json')
        else:
            shutil.copy2(ROOT/'tests/reference-openapi.json',cls.root/'docs/openapi.json')
        shutil.copy2(ROOT/'scripts/swagger_lab.py',cls.root/'scripts/swagger_lab.py')
        FakeRust.received=[]
        cls.rust=ThreadingHTTPServer(('127.0.0.1',0),FakeRust)
        cls.thread=threading.Thread(target=cls.rust.serve_forever,daemon=True)
        cls.thread.start()
        cls.port=free_port()
        cls.proc=subprocess.Popen([sys.executable,str(cls.root/'scripts/swagger_lab.py'),
                        '--port',str(cls.port),'--backend-port',str(cls.rust.server_port),'--root',str(cls.root)],
                        stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        for _ in range(80):
            try:
                conn=http.client.HTTPConnection('127.0.0.1',cls.port,timeout=0.4)
                conn.request('GET','/docs')
                resp=conn.getresponse(); page=resp.read().decode(); conn.close()
                cls.token=re.search(r'<meta name="lab-token" content="([^\"]+)"',page).group(1)
                break
            except (OSError,AttributeError):
                if cls.proc.poll() is not None:
                    raise RuntimeError(cls.proc.stderr.read().decode())
                time.sleep(.05)
        else:
            raise RuntimeError('Servidor UI nao iniciou')

    @classmethod
    def tearDownClass(cls):
        cls.proc.terminate()
        try: cls.proc.wait(timeout=3)
        except subprocess.TimeoutExpired:
            cls.proc.kill();cls.proc.wait()
        cls.rust.shutdown();cls.rust.server_close();cls.temp.cleanup()

    def req(self,method,path,body=None,extra=None):
        headers={'Host':f'127.0.0.1:{self.port}'}
        if extra: headers.update(extra)
        conn=http.client.HTTPConnection('127.0.0.1',self.port,timeout=3)
        conn.request(method,path,body=body,headers=headers)
        response=conn.getresponse()
        status=response.status
        headers=dict(response.getheaders())
        payload=response.read()
        conn.close()
        return status,headers,payload

    def test_01_local_ui_is_served(self):
        status,headers,page=self.req('GET','/docs')
        self.assertEqual(status,200)
        self.assertIn(b'Swagger UI',page)
        self.assertIn(b'swagger-ui-dist@5.33.0',page)
        self.assertIn('frame-ancestors',headers['Content-Security-Policy'])

    def test_02_offline_ui_is_served(self):
        self.assertIn(b'Explorador offline',self.req('GET','/offline')[2])
        self.assertEqual(self.req('GET','/assets/offline.js')[0],200)
        self.assertEqual(self.req('GET','/assets/style.css')[0],200)

    def test_03_openapi_uses_same_origin_only_in_memory(self):
        status,_,raw=self.req('GET','/openapi.json')
        self.assertEqual(status,200)
        spec=json.loads(raw)
        self.assertEqual(spec['openapi'],'3.1.1')
        self.assertEqual(spec['servers'][0]['url'],'/')
        original=json.loads((self.root/'docs/openapi.json').read_text())
        self.assertEqual(original['servers'][0]['url'],'https://localhost:8443')

    def test_04_api_requires_token(self):
        self.assertEqual(self.req('GET','/api/v1/users')[0],403)
        self.assertEqual(self.req('GET','/api/v1/users',extra={'X-Lab-Token':'fake'})[0],403)

    def test_05_valid_proxy_get(self):
        status,headers,data=self.req('GET','/api/v1/users?limit=3',extra={'X-Lab-Token':self.token})
        self.assertEqual(status,200)
        self.assertIn('data',json.loads(data))
        self.assertIn(('GET','/api/v1/users?limit=3',b'',None),FakeRust.received)

    def test_06_valid_proxy_post_location(self):
        body=b'{"name":"Ana Silva","email":"ana@example.com"}'
        status,headers,data=self.req('POST','/api/v1/users',body,
                       {'X-Lab-Token':self.token,'Content-Type':'application/json'})
        self.assertEqual(status,201)
        self.assertEqual(headers['Location'],'/api/v1/users/1')
        self.assertEqual(json.loads(data)['data']['id'],1)
        self.assertIn(('POST','/api/v1/users',body,None),FakeRust.received)

    def test_07_blocks_cross_site_origin(self):
        status,_,_=self.req('DELETE','/api/v1/users/1',extra={
                     'X-Lab-Token':self.token,'Origin':'https://evil.example'})
        self.assertEqual(status,403)

    def test_08_does_not_proxy_metrics(self):
        self.assertEqual(self.req('GET','/metrics',extra={'X-Lab-Token':self.token})[0],404)
        self.assertEqual(self.req('GET','/api/v1/admin',extra={'X-Lab-Token':self.token})[0],404)

    def test_09_host_rebinding_rejected(self):
        self.assertEqual(self.req('GET','/docs',extra={'Host':'other.example'})[0],403)

    def test_10_no_cors_preflight(self):
        status,headers,_=self.req('OPTIONS','/api/v1/users',extra={'Origin':'https://evil.example'})
        self.assertEqual(status,405)
        self.assertNotIn('Access-Control-Allow-Origin',headers)

    def test_11_delete_204_preserved(self):
        status,_,payload=self.req('DELETE','/api/v1/users/1',extra={'X-Lab-Token':self.token})
        self.assertEqual(status,204)
        self.assertEqual(payload,b'')

    def test_12_404_for_unlisted_files(self):
        self.assertEqual(self.req('GET','/../server.rs')[0],404)
        self.assertEqual(self.req('GET','/docs/openapi.yaml')[0],404)

if __name__ == '__main__':
    unittest.main(verbosity=2)
