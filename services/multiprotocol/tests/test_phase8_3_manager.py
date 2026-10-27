from pathlib import Path
import tempfile, subprocess, os, sys, json, shutil, re
MANAGER=str(Path(__file__).resolve().parents[1] / 'scripts/gerenciar_dispositivos_fase8_3.py')
BASE='''# Política de menor privilégio: nenhum tópico fora das regras é autorizado.
user bridge
topic read lab/alerts
topic read lab/sensors/#
topic write bus/alerts
topic write bus/sensors/#

user lab
topic write lab/alerts
topic write lab/sensors/#
topic read bus/alerts
topic read bus/sensors/#
'''
with tempfile.TemporaryDirectory() as tmp:
  root=Path(tmp)/'.config/rust-server/mosquitto'; root.mkdir(parents=True,mode=0o700); root.chmod(0o700)
  for filename,txt in {'acl':BASE,'passwords':'bridge:$fake$bridge\nlab:$fake$lab\n','mosquitto.conf':f'listener 8883 127.0.0.1\nallow_anonymous false\npassword_file {root}/passwords\nacl_file {root}/acl\ncertfile /any/cert.crt\nkeyfile /any/key.key\ntls_version tlsv1.2\nmessage_size_limit 2048\nmax_packet_size 8192\n'}.items():
    (root/filename).write_text(txt); (root/filename).chmod(0o600)
  bin=Path(tmp)/'bin';bin.mkdir(); exe=bin/'mosquitto_passwd'
  exe.write_text('''#!/usr/bin/env python3
import pathlib, sys, base64, hashlib
assert sys.argv[1] == '-U'
p=pathlib.Path(sys.argv[2]); text=p.read_text(); user,pwd=text.rstrip().split(':',1)
p.write_text(user+':$mock$'+hashlib.sha256(pwd.encode()).hexdigest()+'\\n')
'''); exe.chmod(0o755)
  env=os.environ.copy();env['PATH']=str(bin)+':'+env['PATH']; env['HOME']=tmp
  def cmd(*args, ok=True):
    c=subprocess.run([sys.executable,MANAGER,'--mosquitto-dir',str(root),*args],capture_output=True,text=True,env=env)
    print(args, 'RC=',c.returncode, c.stdout.strip(),c.stderr.strip())
    assert (c.returncode==0) == ok
    return c
  cmd('init'); assert 'message_size_limit' not in (root/'mosquitto.conf').read_text()
  cmd('create','sensor01');cmd('create','sensor02');cmd('list')
  pw=(root/'passwords').read_text();assert 'bridge:$fake$bridge' in pw and 'lab:$fake$lab' in pw
  assert len(re.findall(r'device-sensor01',pw))==1
  acl=(root/'acl').read_text();assert 'topic read bus/sensors/sensor01/#' in acl
  base_lab = acl.split('user lab\n',1)[1].split('user device-',1)[0]
  assert 'topic read bus/sensors/#' not in base_lab
  assert 'topic write lab/sensors/#' not in base_lab
  assert 'topic write lab/alerts' in base_lab

  cred=(root.parent/'device-tokens/sensor01.token'); assert cred.exists() and cred.stat().st_mode&0o077 == 0
  cmd('create','sensor01',ok=False)
  cmd('create','../evil',ok=False)
  cmd('rotate','sensor02')
  # Impedir gravacao parcial ao encontrar token apontando para symlink.
  safe_token=cred.with_suffix('.safe')
  cred.rename(safe_token)
  cred.symlink_to(safe_token)
  cmd('revoke','sensor01',ok=False)
  assert json.loads((root/'devices.json').read_text())['devices']['sensor01']['state']=='active'
  cred.unlink(); safe_token.rename(cred)
  cmd('revoke','sensor01');cmd('list')
  assert 'device-sensor01:' not in (root/'passwords').read_text()
  assert 'user device-sensor01' not in (root/'acl').read_text()
  assert not cred.exists()
  cmd('rotate','sensor01',ok=False)
  cmd('init'); cmd('list')
  # Force inconsistent data and ensure fail-closed.
  (root/'passwords').write_text((root/'passwords').read_text().replace('device-sensor02:', 'device-broken:'))
  cmd('create','sensor03',ok=False)
  # Diretorio configurado nao pode ser um symlink.
  symlink_root=Path(tmp)/'linked-mosquitto'
  symlink_root.symlink_to(root, target_is_directory=True)
  rejected=subprocess.run([sys.executable,MANAGER,'--mosquitto-dir',str(symlink_root),'list'],
                          capture_output=True,text=True,env=env)
  assert rejected.returncode != 0 and 'link simbolico' in rejected.stderr
print('PASSED: offline mock smoke tests')
