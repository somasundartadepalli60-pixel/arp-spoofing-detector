"""Local simulator messaging. Does not transmit ARP packets or collect credentials."""
import json
import re
import secrets
import time
from pathlib import Path
from uuid import uuid4

MAC_PATTERN = re.compile(r'(?:[0-9a-f]{2}:){5}[0-9a-f]{2}', re.I)

def create_session(directory, baseline, info):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    data = {'token':secrets.token_hex(24), 'baseline':dict(baseline), 'info':dict(info), 'created':time.time()}
    path=directory/'session.json';tmp=directory/'session.tmp'
    tmp.write_text(json.dumps(data),encoding='utf-8');tmp.replace(path)
    return data

def submit_request(directory, target_ip=None, fake_mac=None):
    directory=Path(directory)
    try:data=json.loads((directory/'session.json').read_text(encoding='utf-8'))
    except (OSError,ValueError):raise ValueError('Start Monitoring or Start Local Demo in the detector first.')
    if time.time()-data.get('created',0)>86400:raise ValueError('The demo session has expired. Restart monitoring.')
    baseline=data['baseline']
    target_ip=target_ip or next(iter(baseline),None)
    if target_ip not in baseline:raise ValueError('Choose a claimed IP shown in the trusted baseline. A random new IP is not a spoofed existing device.')
    fake_mac=(fake_mac or ('02:'+':'.join(f'{v:02x}' for v in secrets.token_bytes(5)))).lower().replace('-',':')
    if not MAC_PATTERN.fullmatch(fake_mac) or int(fake_mac[:2],16)&1 or fake_mac=='00:00:00:00:00:00':raise ValueError('Use a valid unicast MAC address.')
    if fake_mac==baseline[target_ip]:raise ValueError('The demo MAC must differ from the trusted MAC.')
    request={'token':data['token'],'claimed_ip':target_ip,'fake_mac':fake_mac,'created':time.time()}
    uid=uuid4().hex;temporary=directory/(uid+'.tmp');path=directory/(uid+'.json')
    temporary.write_text(json.dumps(request),encoding='utf-8');temporary.replace(path)
    return request,path

def take_requests(directory, session):
    for path in Path(directory).glob('*.json'):
        if path.name=='session.json':continue
        try:
            if path.stat().st_size>4096:continue
            request=json.loads(path.read_text(encoding='utf-8'))
            mac=request.get('fake_mac','')
            if (request.get('token')==session.get('token') and abs(time.time()-request.get('created',0))<60
                and request.get('claimed_ip') in session['baseline'] and MAC_PATTERN.fullmatch(mac)
                and not int(mac[:2],16)&1 and mac!='00:00:00:00:00:00'
                and mac!=session['baseline'][request['claimed_ip']]):
                yield request
        except (OSError,ValueError,TypeError,KeyError):pass
        finally:
            try:path.unlink(missing_ok=True)
            except OSError:pass

def end_session(directory):
    try:(Path(directory)/'session.json').unlink(missing_ok=True)
    except OSError:pass
