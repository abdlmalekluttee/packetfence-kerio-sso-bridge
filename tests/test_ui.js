const fs=require('node:fs'),vm=require('node:vm'),assert=require('node:assert/strict'),path=require('node:path');
class Element {
  constructor(){this.children=[];this.value='';this.checked=false;this.textContent='';this.handlers={};}
  append(...items){this.children.push(...items)}
  replaceChildren(...items){this.children=items}
  addEventListener(event,fn){this.handlers[event]=fn}
  set innerHTML(value){throw Error('Unsafe HTML sink used')}
}
const nodes=new Map();const requests=[];
const context={document:{createElement:()=>new Element(),getElementById:id=>{
  if(!nodes.has(id))nodes.set(id,new Element());return nodes.get(id)},addEventListener(){}},
  fetch:async(url,opt)=>{requests.push({url,opt});return{ok:true,json:async()=>url==='/api/kerios'?[]:{csrf:'dummy'}}},
  confirm:()=>true,setTimeout:()=>0,console};
vm.createContext(context);
vm.runInContext(fs.readFileSync(path.join(__dirname,'../bridge/ui.js'),'utf8'),context);
const name="O'Brien <img src=x onerror=alert(1)>";
context.renderTargets([{id:'k1',name,host:'kerio.test',port:4081,user:'api',subnets:[],verify:true,enabled:true,override_manual:true,domains:['hiss.local','tanasuh.local'],domain_aliases:{hiss:'hiss.local'}}]);
const row=nodes.get('targets').children[0];assert.equal(row.children[0].textContent,name);
row.children.at(-1).children[1].handlers.click();assert.equal(nodes.get('name').value,name);
assert.equal(nodes.get('override_manual').checked,true);
assert.equal(nodes.get('domains').value,'hiss.local, tanasuh.local');
assert.deepEqual(JSON.parse(nodes.get('domain_aliases')?.value||'{}'),{hiss:'hiss.local'});
nodes.get('override_manual').checked=false;
context.saveTarget({preventDefault(){}}).then(async()=>{
  const req=requests.find(x=>x.opt?.method==='POST');assert(req);
  assert.equal(JSON.parse(req.opt.body).override_manual,false);
  assert.equal(JSON.parse(req.opt.body).password,'');
  assert.deepEqual(JSON.parse(req.opt.body).domains,['hiss.local','tanasuh.local']);
  assert.deepEqual(JSON.parse(req.opt.body).domain_aliases,{hiss:'hiss.local'});
  const count=requests.length;nodes.get('domain_aliases').value='{invalid';
  await context.saveTarget({preventDefault(){}});
  assert.equal(requests.length,count);assert.equal(nodes.get('message').className,'error');
  console.log('GUI safe rendering and override toggle: PASS');
}).catch(error=>{console.error(error);process.exitCode=1});
