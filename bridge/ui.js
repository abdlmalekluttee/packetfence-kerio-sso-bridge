'use strict';
let csrf='';
const field=id=>document.getElementById(id);
async function api(url,options={}) {
  if(options.method==='POST') {
    if(!csrf) csrf=(await api('/api/session')).csrf;
    options.headers={'Content-Type':'application/json','X-CSRF-Token':csrf};
  }
  const response=await fetch(url,options);
  const data=await response.json();
  if(!response.ok) throw new Error(data.error||'Request failed');
  return data;
}
function message(text,error=false){field('message').textContent=text;field('message').className=error?'error':''}
function button(label,action,kind='secondary') {
  const element=document.createElement('button');element.type='button';element.textContent=label;
  element.className=kind;element.addEventListener('click',action);return element;
}
function renderTargets(targets) {
  const rows=targets.map(target=>{
    const row=document.createElement('tr');
    const values=[target.name,`${target.host}:${target.port}`,target.user,(target.domains||[]).join(', ')||'Any',(target.subnets||[]).join(', ')||'Any',
      `${target.enabled?'Enabled':'Disabled'} · manual override ${target.override_manual?'on':'off'}${target.verify?'':' · TLS unverified'}`];
    for(const value of values){const cell=document.createElement('td');cell.textContent=value;row.append(cell)}
    const actions=document.createElement('td');
    actions.append(button('Test',()=>testTarget(target.id)),button('Edit',()=>editTarget(target)),button('Delete',()=>deleteTarget(target),'danger'));
    row.append(actions);return row;
  });field('targets').replaceChildren(...rows);
}
function clearForm(){
  for(const id of ['id','name','host','user','password','default_domain','prefix','suffix','subnets','ca_file','domains','domain_aliases'])field(id).value='';
  field('port').value='4081';field('enabled').checked=true;field('verify').checked=true;field('override_manual').checked=false;
  field('form-title').textContent='Add Kerio firewall';
}
function editTarget(target){
  for(const id of ['id','name','host','user','port','default_domain','prefix','suffix','ca_file'])field(id).value=target[id]||'';
  field('password').value='';field('subnets').value=(target.subnets||[]).join(', ');
  field('domains').value=(target.domains||[]).join(', ');field('domain_aliases').value=JSON.stringify(target.domain_aliases||{});
  for(const id of ['enabled','verify','override_manual'])field(id).checked=Boolean(target[id]);
  field('form-title').textContent='Edit '+target.name;
}
async function saveTarget(event){
  event.preventDefault();
  const body={};for(const id of ['id','name','host','user','password','port','default_domain','prefix','suffix','ca_file'])body[id]=field(id).value;
  for(const id of ['enabled','verify','override_manual'])body[id]=field(id).checked;
  body.subnets=field('subnets').value.split(',').map(s=>s.trim()).filter(Boolean);
  body.domains=field('domains').value.split(',').map(s=>s.trim()).filter(Boolean);
  try{body.domain_aliases=JSON.parse(field('domain_aliases').value||'{}');
    await api('/api/kerios',{method:'POST',body:JSON.stringify(body)});clearForm();message('Saved');await loadTargets()}
  catch(error){message(error.message,true)}
}
async function loadTargets(){renderTargets(await api('/api/kerios'))}
async function testTarget(id){
  try{const result=await api('/api/kerios/test',{method:'POST',body:JSON.stringify({id})});message(`API reachable: ${result.activeHosts} active hosts`)}
  catch(error){message(error.message,true)}
}
async function deleteTarget(target){
  if(!confirm(`Delete ${target.name}? Active or pending leases must be revoked first.`))return;
  try{await api('/api/kerios/delete',{method:'POST',body:JSON.stringify({id:target.id})});await loadTargets();message('Deleted')}
  catch(error){message(error.message,true)}
}
async function refreshStatus(){
  try{
    const status=await api('/api/status');
    field('status').textContent=`${status.active} tracked mappings · ${status.waiting||0} waiting for device traffic · ${status.held||0} held for PacketFence checks · ${status.failed===undefined?status.pending:status.failed} failures${status.worker_error?' · worker needs attention':''}${status.source_error?' · PacketFence API needs attention':''}`;
    const rows=status.leases.filter(lease=>lease.error).map(lease=>{
      const row=document.createElement('p');row.className='pending';row.textContent=`${lease.ip} · ${lease.user}: ${lease.error}`;return row;
    });field('pending').replaceChildren(...rows);
  }catch(error){field('status').textContent='Status unavailable: '+error.message}
  setTimeout(refreshStatus,15000);
}
document.addEventListener('DOMContentLoaded',()=>{
  field('target-form').addEventListener('submit',saveTarget);
  field('clear').addEventListener('click',clearForm);
  loadTargets().catch(error=>message(error.message,true));refreshStatus();
});
