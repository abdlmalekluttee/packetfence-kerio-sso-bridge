import copy
from bridge.kerio import KerioClient

CONFIG = {'id':'k1','name':'Test','host':'kerio.invalid','port':4081,
          'user':'api','password':'not-a-real-secret','verify':True,
          'enabled':True,'subnets':[],'default_domain':'example.test'}

def host(user='alice', domain='example.test', ip='192.0.2.10', method='AuthMethodApi'):
    return {'id':'h1','type':'ActiveHostHost','ip':ip,'ip6Addresses':['2001:db8::10'],
            'macAddress':'02:00:00:00:00:01','authMethod':method,
            'user':{'id':'u-'+user if user else '', 'name':user,'domainName':domain,'isGroup':False}}

class Appliance(KerioClient):
    """Network boundary double; all real client logic remains in use."""
    def __init__(self, cfg=None):
        super().__init__({**CONFIG, **(cfg or {})})
        self.calls=[]
        self.hosts=[host()]
        self.users=[{'id':'u-alice','credentials':{'userName':'alice'},'autoLogin':{
            'addresses':{'enabled':True,'value':['192.0.2.10','192.0.2.20']},
            'macAddresses':{'enabled':False,'value':[]},
            'addressGroup':{'enabled':False,'id':'','name':''}}},
            {'id':'u-bob','credentials':{'userName':'bob'},'autoLogin':{
            'addresses':{'enabled':False,'value':[]},'macAddresses':{'enabled':False,'value':[]},
            'addressGroup':{'enabled':False,'id':'','name':''}}}]
        self.fail={}
    def _exchange(self, payload, headers):
        method=payload['method']; p=payload['params']; self.calls.append((method,copy.deepcopy(p)))
        failure=self.fail.get(method)
        if failure:
            if callable(failure): return failure(payload)
            raise failure
        if method=='Session.login': result={'token':'test-token'}
        elif method=='ActiveHosts.get':
            q=p['query']; result={'list':copy.deepcopy(self.hosts[q['start']:q['start']+q['limit']]),'totalItems':len(self.hosts)}
        elif method=='ActiveHosts.logout':
            assert p['ids']
            for h in self.hosts:
                if h['id'] in p['ids']: h['user']={'id':'','name':'','domainName':'','isGroup':False}
            result={}
        elif method=='ActiveHosts.login':
            name,_,domain=p['userName'].partition('@')
            for h in self.hosts:
                if h['id']==p['hostId']: h['user']={'id':'u-'+name,'name':name,'domainName':domain or 'example.test','isGroup':False}; h['authMethod']='AuthMethodApi'
            result={}
        elif method=='Domains.get': result={'list':[{'id':'d1','service':{'domainName':'example.test'}}], 'totalItems':1}
        elif method=='Users.get':
            rows=self.users if p['domainId']=='d1' else []
            q=p['query']; result={'warnings':[],'list':copy.deepcopy(rows[q['start']:q['start']+q['limit']]),'totalItems':len(rows)}
        elif method=='Users.set':
            for u in self.users:
                if u['id'] in p['userIds']: u['autoLogin']=copy.deepcopy(p['details']['autoLogin'])
            result={'errors':[]}
        elif method=='Session.logout': result={}
        else: raise AssertionError('unexpected RPC '+method)
        return {'jsonrpc':'2.0','id':payload['id'],'result':result}

    def mutations(self):
        return [(m,p) for m,p in self.calls if m in ('ActiveHosts.login','ActiveHosts.logout','Users.set')]

class Clock:
    def __init__(self): self.now=1000.
    def __call__(self): return self.now
    def advance(self,n): self.now+=n
