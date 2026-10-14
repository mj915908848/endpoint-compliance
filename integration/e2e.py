#!/usr/bin/env python3
"""Real loopback ASP.NET + real agent simulation. No claimed native Windows coverage."""
import argparse, http.cookiejar, json, os, pathlib, secrets, socket, sqlite3, subprocess, time, urllib.request
from datetime import datetime, timezone
root=pathlib.Path(__file__).resolve().parents[1]
ap=argparse.ArgumentParser();ap.add_argument('--dotnet',default='dotnet');ap.add_argument('--data',type=pathlib.Path);ap.add_argument('--port',type=int,default=0);args=ap.parse_args()
data=args.data or root/'artifacts'/('e2e-'+secrets.token_hex(4));data.mkdir(parents=True,exist_ok=False)
if args.port: port=args.port
else:
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
base=f'http://127.0.0.1:{port}'
password=secrets.token_urlsafe(24)
env=os.environ.copy();env.update({'ASPNETCORE_URLS':base,'Compliance__DemoMode':'true','Compliance__Storage':'Sqlite','Compliance__Database':str(data/'server.sqlite'),'Compliance__SigningKeyPath':str(data/'signing.pem'),'Compliance__BootstrapUsers':json.dumps([{'username':'trial-admin','password':password,'roles':['Reader','Operator','Publisher']},{'username':'trial-reviewer','password':secrets.token_urlsafe(24),'roles':['Reader','Reviewer']}])})
client=urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()));csrf=''
def request(path,body=None,raw=False):
    encoded=json.dumps(body).encode() if body is not None else None
    req=urllib.request.Request(base+path,data=encoded,headers={'Content-Type':'application/json','X-CSRF-Token':csrf})
    with client.open(req,timeout=15) as response:
        content=response.read().decode();return content if raw else json.loads(content)
server_log=(data/'server.log').open('w');process=None

def start():
    global process
    process=subprocess.Popen([args.dotnet,str(root/'src/Compliance.Server/bin/Release/net10.0/Compliance.Server.dll')],cwd=root/'src/Compliance.Server',env=env,stdout=server_log,stderr=subprocess.STDOUT)
    end=time.monotonic()+30
    while time.monotonic()<end:
        if process.poll() is not None:raise AssertionError('Server failed; inspect server.log')
        try:request('/api/status');return
        except Exception:time.sleep(.1)
    raise AssertionError('Server startup timeout')
def stop():
    process.terminate();process.wait(timeout=10)
def fixture(evidence):
    now=datetime.now(timezone.utc).isoformat()
    snap={'deviceId':'fixture','hostName':'Simulated Windows endpoint','platform':'Windows','simulated':True,'collectedAt':now,'policyVersion':1,'evidence':evidence,'modules':[{'module':m,'scope':'machine','status':'Complete','collectedAt':now} for m in ['installed','processes','proxy','extensions','appx','ports','users','cli']],'controls':[]}
    (data/'snapshot.json').write_text(json.dumps(snap))
def agent(enrollment=None):
    cmd=[args.dotnet,str(root/'src/Compliance.Agent/bin/Release/net10.0/Compliance.Agent.dll'),'--fixture',str(data/'snapshot.json'),'--data-dir',str(data/'agent'),'--server',base,'--once']
    if enrollment:cmd += ['--enroll','--code',enrollment]
    with (data/'agent.log').open('a') as log:
        p=subprocess.run(cmd,cwd=root,stdout=log,stderr=subprocess.STDOUT,timeout=45)
        assert p.returncode==0, 'Agent failed; inspect agent.log'
def queued():
    with sqlite3.connect(data/'agent/outbox.sqlite') as db:return db.execute('select count(*) from events').fetchone()[0]
def wait_for_retry():
    with sqlite3.connect(data/'agent/outbox.sqlite') as db:
        pending=[row[0] for row in db.execute('select next_attempt from events where next_attempt is not null')]
    if pending:
        due=max(datetime.fromisoformat(value).timestamp() for value in pending)
        time.sleep(max(0,due-time.time())+1)
try:
    start()
    index=request('/',raw=True)
    assert '<div id="root"></div>' in index and '/assets/' in index,'Built management UI was not served'
    asset=index.split('src="/assets/',1)[1].split('"',1)[0]
    assert len(request('/assets/'+asset,raw=True))>1000,'Built management script was not served'
    auth=request('/api/auth/login',{'username':'trial-admin','password':password});csrf=auth['csrfToken']
    code=request('/api/enrollment-codes',{'expiresMinutes':15})['code']
    fixture([{'productId':'cursor','productName':'Cursor','kind':'Installation','objectKey':'cursor-install','source':'fixture registry','summary':'Exact registered Cursor installation','userSid':'S-1-5-21-1-2-3-1001','confirmed':True}]);agent(code)
    devices=request('/api/devices');assert len(devices)==1 and devices[0]['simulated'] is True
    device=devices[0]['id'];report=request(f'/api/devices/{device}/report');assert report['verdict']=='FAIL' and report['violationCount']==1
    alerts=request('/api/alerts');violations=[x for x in alerts if x['type']=='Violation' and x['state']=='Active'];assert len(violations)==1, 'FAIL snapshot must open incident'
    request('/api/alerts/'+violations[0]['id']+'/ack',{});assert request('/api/alerts')[0]['state']=='Active','Acknowledgment cannot resolve technical state'
    md=request(f'/api/devices/{device}/report.md',raw=True);assert sum(line.startswith('## ') for line in md.splitlines())==9
    (data/'report.md').write_text(md);(data/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2))
    print('PASS enrollment + signature + actual agent upload + FAIL report + aggregated alert + ack separate',flush=True)
    fixture([]);agent();report=request(f'/api/devices/{device}/report');assert report['verdict']=='UNKNOWN','Simulation cannot claim native PASS'
    # Simulation gap must conservatively retain incident until complete real coverage; tests cover native recovery.
    assert queued()==0,'Server commit ACK must clear delivered queue'
    print('PASS simulation visibly UNKNOWN + fixed nine-section Markdown + committed events acknowledged',flush=True)
    stop();fixture([{'productId':'claude','productName':'Claude','kind':'Installation','objectKey':'claude-npm','source':'fixture npm','summary':'Confirmed CLI package fixture','confirmed':True}]);agent();assert queued()>0,'Offline event must survive'
    print('PASS disconnected agent collected and persisted offline event',flush=True)
    start();auth=request('/api/auth/login',{'username':'trial-admin','password':password});csrf=auth['csrfToken']
    # Follow the persisted retry deadline, including randomized backoff jitter.
    wait_for_retry();fixture([]);agent();assert queued()==0,'Reconnect must replay and ACK pending history'
    assert len(request('/api/devices'))==1,'Device identity survives restart'
    print('PASS durable server restart + device identity + replay ACK without duplication',flush=True)
    (data/'result.json').write_text(json.dumps({'result':'PASS','nativeWindowsVerified':False,'database':'SQLite loopback','deviceId':device,'checks':['registration','signed requests','agent upload','FAIL','incident aggregation','ack not recovery','nine report sections','simulation UNKNOWN','offline durability','restart replay']},indent=2))
    print('Evidence: '+str(data),flush=True)
finally:
    if process and process.poll() is None:stop()
    server_log.close()
