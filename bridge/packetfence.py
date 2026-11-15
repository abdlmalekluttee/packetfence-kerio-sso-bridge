"""Optional read-only PacketFence authority checks; uncertainty never authorizes writes."""
import hashlib
import hmac
import http.client
import ipaddress
import json
import re
import socket
import ssl
import threading
import time
from datetime import datetime, timezone
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError


class SourceError(Exception):
    pass


def mac(value):
    value = re.sub('[:-]', '', value).lower() if isinstance(value, str) else ''
    return value if re.fullmatch('[0-9a-f]{12}', value) else ''


class PacketFence:
    def __init__(self, cfg, clock=time.time):
        self.clock = clock
        self.host = cfg.get('host', '')
        if not isinstance(self.host, str) or not re.fullmatch(r'[a-zA-Z0-9][a-zA-Z0-9.-]{0,252}', self.host):
            raise ValueError('Invalid PacketFence host')
        self.port = cfg.get('port', 9999)
        if type(self.port) is not int or not 1 <= self.port <= 65535:
            raise ValueError('Invalid PacketFence port')
        self.username, self.password = cfg.get('username'), cfg.get('password')
        if any(not isinstance(v,str) or not v or len(v)>1024 or any(ord(c)<32 for c in v)
               for v in (self.username,self.password)):
            raise ValueError('PacketFence API credentials required')
        self.pin = cfg.get('certificate_sha256', '')
        if not isinstance(self.pin,str) or (self.pin and not re.fullmatch('[0-9a-fA-F]{64}',self.pin)):
            raise ValueError('Invalid PacketFence certificate pin')
        try:
            zone = cfg.get('timezone', 'UTC')
            self.timezone = timezone.utc if zone == 'UTC' else ZoneInfo(zone)
        except (ZoneInfoNotFoundError, TypeError) as ex:
            raise ValueError('Invalid PacketFence timezone') from ex
        self.context = (ssl._create_unverified_context() if self.pin
                        else ssl.create_default_context(cafile=cfg.get('ca_file') or None))
        self.context.minimum_version = ssl.TLSVersion.TLSv1_2
        self._lock = threading.RLock()
        self._cache = {}
        self._token = None
        self._retry_at = 0
        self._failures = 0
        self.error = None

    def _exchange(self, path, payload, token):
        conn = http.client.HTTPSConnection(self.host,self.port,context=self.context,timeout=5)
        def expire():
            if conn.sock:
                try: conn.sock.shutdown(socket.SHUT_RDWR)
                except OSError: pass
                conn.close()
        timer = threading.Timer(8,expire);timer.daemon=True;timer.start()
        try:
            conn.connect()
            if self.pin and not hmac.compare_digest(
                    hashlib.sha256(conn.sock.getpeercert(binary_form=True)).hexdigest(),self.pin.lower()):
                raise SourceError('PacketFence TLS certificate changed')
            headers = {'Content-Type':'application/json','Accept':'application/json'}
            if token: headers['Authorization']='Bearer '+token
            conn.request('POST','/api/v1'+path,json.dumps(payload),headers)
            response=conn.getresponse()
            if response.status == 401:
                self._token=None
            if response.status != 200:
                raise SourceError('PacketFence API request rejected')
            data=response.read(2*1024*1024+1)
            if len(data)>2*1024*1024:raise SourceError('PacketFence response too large')
            value=json.loads(data)
            if not isinstance(value,dict):raise SourceError('Invalid PacketFence response')
            return value
        except (OSError,ValueError,http.client.HTTPException) as ex:
            raise SourceError('PacketFence API unavailable or invalid response') from ex
        finally:
            timer.cancel();conn.close()

    def _search(self, resource, field, values, fields):
        if self._token is None:
            token=self._exchange('/login',{'username':self.username,'password':self.password},None).get('token')
            if not isinstance(token,str) or not token or len(token)>8192:
                raise SourceError('Invalid PacketFence login response')
            self._token=token
        result=self._exchange('/'+resource+'/search',{
            'query':{'op':'or','values':[{'field':field,'op':'equals','value':v} for v in sorted(values)]},
            'fields':fields,'limit':len(values)+1},self._token)
        items=result.get('items')
        if (result.get('status',200)!=200 or result.get('nextCursor') is not None
                or not isinstance(items,list) or len(items)>len(values)
                or any(not isinstance(v,dict) for v in items)):
            raise SourceError('Incomplete PacketFence search result')
        return items

    def _eligible(self,row):
        try:return ipaddress.ip_address(row['ip']).version==4 and bool(mac(row.get('mac')))
        except (ValueError,KeyError):return False

    def refresh(self,rows):
        with self._lock:
            now=self.clock()
            if now<self._retry_at:return
            due=[r for r in rows if self._eligible(r) and
                 now-self._cache.get(r['ip'],{}).get('at',float('-inf'))>=60]
            # Oldest observations first; at most two search calls per refresh.
            due=sorted({r['ip']:r for r in due}.values(),key=lambda r:self._cache.get(r['ip'],{}).get('at',0))[:100]
            if not due:return
            ips={r['ip'] for r in due}
            try:
                bindings=self._search('ip4logs','ip',ips,['ip','mac','start_time','end_time'])
                if any(r.get('ip') not in ips for r in bindings):raise SourceError('Unexpected PacketFence IP')
                macs={mac(r.get('mac')) for r in bindings}
                if '' in macs:raise SourceError('Invalid PacketFence device identity')
                formatted={':'.join(m[i:i+2] for i in range(0,12,2)) for m in macs}
                nodes=self._search('nodes','mac',formatted,['mac','pid','status']) if formatted else []
                if any(mac(n.get('mac')) not in macs for n in nodes):raise SourceError('Unexpected PacketFence node')
                for row in due:
                    self._cache[row['ip']]={'at':now,'bindings':[b for b in bindings if b['ip']==row['ip']],
                        'nodes':[n for n in nodes if any(mac(n.get('mac'))==mac(b['mac'])
                                 for b in bindings if b['ip']==row['ip'])]}
                # Cache capacity follows the durable state's hard bound.
                if len(self._cache)>10000:
                    self._cache=dict(sorted(self._cache.items(),key=lambda kv:kv[1]['at'],reverse=True)[:10000])
                self.error=None;self._failures=0
            except SourceError as ex:
                self.error=str(ex);self._failures+=1
                self._retry_at=now+min(300,30*2**min(self._failures-1,4))

    def observed(self,ip):
        with self._lock:return self._cache.get(ip,{}).get('at',0)

    def check(self,row,canonicalize):
        if not self._eligible(row):return 'unknown'
        with self._lock:
            self.refresh([row])
            snapshot=self._cache.get(row['ip'])
            if not snapshot or self.clock()-snapshot['at']>=60:return 'unknown'
            bindings,nodes=snapshot['bindings'],snapshot['nodes']
            if len(bindings)!=1 or len(nodes)!=1:return 'unknown'
            binding,node=bindings[0],nodes[0]
            if not isinstance(node.get('pid'),str) or not node['pid'] or node.get('status') not in ('reg','unreg','pending'):
                return 'unknown'
            end=binding.get('end_time')
            if end not in ('0000-00-00 00:00:00',None):
                try:ended=datetime.strptime(end,'%Y-%m-%d %H:%M:%S').replace(tzinfo=self.timezone).timestamp()<=self.clock()
                except (ValueError,TypeError):return 'unknown'
                if ended:return 'stale'
            if (mac(binding['mac'])!=mac(row['mac']) or node['status']!='reg'
                    or canonicalize(node['pid'])!=canonicalize(row['user'])):
                return 'stale'
            return 'current'
