const pageMeta = {
  dashboard:["仪表盘","查看 GateSocks 当前运行状态与出口概况"],
  nodes:["节点池","筛选、测试并选择真实可用的候选出口"],
  socks:["SOCKS5","管理已生成的本地与外部 SOCKS5 访问地址"],
  openvpn:["OpenVPN","查看 SOCKS5 背后的 OpenVPN 隧道状态"],
  tests:["测试记录","查看延迟、速度、稳定性与出口检测历史"],
  logs:["日志","查看 GateSocks 当前运行日志"],
  settings:["设置","查看服务参数并管理管理员账号"]
};

const qs = s => document.querySelector(s);
const qsa = s => [...document.querySelectorAll(s)];
let allNodes=[];

function showPage(name){
  qsa(".nav-item").forEach(x=>x.classList.toggle("active",x.dataset.page===name));
  qsa(".page").forEach(x=>x.classList.toggle("active",x.id==="page-"+name));
  qs("#pageTitle").textContent=pageMeta[name][0];
  qs("#pageDesc").textContent=pageMeta[name][1];
  qs("#sidebar").classList.remove("open");
  location.hash=name;
}

qsa(".nav-item").forEach(x=>x.onclick=()=>showPage(x.dataset.page));
qsa("[data-jump]").forEach(x=>x.onclick=()=>showPage(x.dataset.jump));
qs("#menuBtn").onclick=()=>qs("#sidebar").classList.toggle("open");
qs("#refreshBtn").onclick=()=>loadAll();

const reloadLogs=qs("#reloadLogs");
if(reloadLogs) reloadLogs.onclick=()=>loadLogs();

const logoutBtn=qs("#logoutBtn");
if(logoutBtn) logoutBtn.onclick=async()=>{ await fetch("/api/logout",{method:"POST"}); location.replace("/login"); };

const refreshNodesBtn=qs("#refreshNodesBtn");
if(refreshNodesBtn) refreshNodesBtn.onclick=()=>loadNodes(true);

["#countryFilter","#nodeStatusFilter","#nodeSearch"].forEach(sel=>{
  const el=qs(sel);
  if(el) el.addEventListener(sel==="#nodeSearch"?"input":"change",renderNodes);
});

const saveAuthBtn=qs("#saveAuthBtn");
if(saveAuthBtn) saveAuthBtn.onclick=saveAuthSettings;

function kv(label,value){
  const box=document.createElement("div"); box.className="kv";
  const s=document.createElement("span"); s.textContent=label;
  const b=document.createElement("strong"); b.textContent=value;
  box.append(s,b); return box;
}

async function getJson(url,options={}){
  const r=await fetch(url,{cache:"no-store",...options});
  if(r.status===401){ location.replace("/login"); throw new Error("authentication required"); }
  const data=await r.json().catch(()=>({}));
  if(!r.ok) throw new Error(data.detail||url+" "+r.status);
  return data;
}

async function loadMe(){
  try{
    const m=await getJson("/api/me");
    if(!m.authenticated){ location.replace("/login"); return; }
    const el=qs("#currentUser");
    if(el) el.textContent=m.username||"admin";
  }catch(e){}
}

async function loadStatus(){
  try{
    const s=await getJson("/api/status");
    qs("#serviceBadge").textContent="在线";
    qs("#serviceBadge").className="badge";
    qs("#version").textContent="v"+s.version.replace(/^v/,"");
    qs("#statSocks").textContent=s.socks_online;
    qs("#statTunnels").textContent=s.tunnel_count;
    qs("#statNodes").textContent=s.candidate_nodes;
    qs("#statAlerts").textContent=s.alerts;
    const box=qs("#systemInfo"); box.innerHTML="";
    [
      ["版本",s.version],["Python",s.python],["OpenVPN",s.openvpn],
      ["/dev/net/tun",s.tun_present?"可用":"不可用"],
      ["Web 监听",s.bind+":"+s.port],["阶段",s.stage]
    ].forEach(([a,b])=>box.appendChild(kv(a,b)));
  }catch(e){
    qs("#serviceBadge").textContent="离线";
  }
}

function statusText(value){
  return {candidate:"候选",available:"可用",testing:"测试中",unavailable:"不可用"}[value]||value||"-";
}

function renderNodes(){
  const table=qs("#nodesTable");
  if(!table) return;
  const country=(qs("#countryFilter")?.value||"").toUpperCase();
  const status=qs("#nodeStatusFilter")?.value||"";
  const search=(qs("#nodeSearch")?.value||"").trim().toLowerCase();
  const items=allNodes.filter(n=>{
    if(country && n.country_short!==country) return false;
    if(status && n.status!==status) return false;
    if(search){
      const hay=[n.ip,n.hostname,n.country_short,n.country_long,n.operator].join(" ").toLowerCase();
      if(!hay.includes(search)) return false;
    }
    return true;
  });

  table.innerHTML="";
  if(!items.length){
    const tr=document.createElement("tr");
    const td=document.createElement("td"); td.colSpan=11;
    const empty=document.createElement("div"); empty.className="empty compact"; empty.textContent="没有符合当前筛选条件的节点";
    td.appendChild(empty); tr.appendChild(td); table.appendChild(tr); return;
  }

  items.forEach(n=>{
    const tr=document.createElement("tr");
    const values=[
      n.country_short||"-",
      n.ip||"-",
      "待实测",
      "待实测",
      n.source_ping_ms==null?"-":n.source_ping_ms+" ms*",
      n.source_speed_mbps==null?"-":n.source_speed_mbps+" Mbps*",
      "-",
      "-",
      "待实测",
      statusText(n.status)
    ];
    values.forEach(value=>{
      const td=document.createElement("td"); td.textContent=value; tr.appendChild(td);
    });
    const action=document.createElement("td");
    const button=document.createElement("button"); button.className="btn ghost"; button.disabled=true; button.textContent="待实测";
    action.appendChild(button); tr.appendChild(action); table.appendChild(tr);
  });
}

function fillCountryFilter(){
  const select=qs("#countryFilter");
  if(!select) return;
  const current=select.value;
  const countries=[...new Set(allNodes.map(n=>n.country_short).filter(Boolean))].sort();
  select.innerHTML="";
  const all=document.createElement("option"); all.value=""; all.textContent="全部地区"; select.appendChild(all);
  countries.forEach(code=>{
    const o=document.createElement("option"); o.value=code; o.textContent=code; select.appendChild(o);
  });
  if(countries.includes(current)) select.value=current;
}

async function loadNodes(refresh=false){
  const meta=qs("#nodeSourceMeta");
  const button=qs("#refreshNodesBtn");
  if(button){button.disabled=true;button.textContent=refresh?"刷新中…":"读取中…";}
  if(meta) meta.textContent=refresh?"正在从 VPN Gate 重新拉取候选节点…":"正在读取 VPN Gate 候选节点…";
  try{
    const data=await getJson(refresh?"/api/nodes/refresh":"/api/nodes",refresh?{method:"POST"}:{});
    allNodes=data.items||[];
    fillCountryFilter();
    renderNodes();
    const count=data.count??allNodes.length;
    const updated=data.updated_at?new Date(data.updated_at).toLocaleString():"尚未缓存";
    if(meta) meta.textContent=`来源：${data.source||"VPN Gate"} · 候选 ${count} 个 · 更新：${updated} · * Ping/Speed 为公益源公布值，不代表本 VPS 实测`;
    if(qs("#statNodes")) qs("#statNodes").textContent=count;
  }catch(e){
    allNodes=[];
    renderNodes();
    if(meta) meta.textContent="节点池读取失败："+e.message;
  }finally{
    if(button){button.disabled=false;button.textContent="拉取节点";}
  }
}

async function loadOpenVPN(){
  try{
    const o=await getJson("/api/openvpn");
    const info=qs("#openvpnInfo"); info.innerHTML="";
    [["OpenVPN",o.version],["TUN 设备",o.tun_present?"可用":"不可用"],["当前隧道",o.tunnels.length]].forEach(([a,b])=>info.appendChild(kv(a,b)));
    qs("#tunBadge").textContent=o.tun_present?"TUN 可用":"TUN 不可用";
    qs("#tunBadge").className="pill "+(o.tun_present?"ok":"");
    const list=qs("#tunnelList"); list.innerHTML="";
    if(!o.tunnels.length){ list.innerHTML='<div class="empty">当前没有活动的 TUN/TAP 隧道</div>'; return; }
    o.tunnels.forEach(t=>{
      const d=document.createElement("div"); d.className="proxy-card";
      const head=document.createElement("div"); head.className="proxy-head";
      const left=document.createElement("div");
      const strong=document.createElement("strong"); strong.textContent=t.name;
      const span=document.createElement("span"); span.textContent="OpenVPN/TUN interface";
      left.append(strong,span);
      const state=document.createElement("span"); state.className="pill ok"; state.textContent=t.state;
      head.append(left,state); d.appendChild(head); list.appendChild(d);
    });
  }catch(e){}
}

async function loadSettings(){
  try{
    const s=await getJson("/api/settings");
    qs("#webBind").value=s.web.bind;
    qs("#webPort").value=s.web.port;
    if(qs("#settingsUsername")) qs("#settingsUsername").value=s.auth.username||"";
    if(qs("#authSource")) qs("#authSource").textContent=s.auth.source==="panel"?"面板持久化":"环境变量";
  }catch(e){}
}

async function saveAuthSettings(){
  const message=qs("#authMessage");
  const button=qs("#saveAuthBtn");
  const username=qs("#settingsUsername").value.trim();
  const currentPassword=qs("#currentPassword").value;
  const newPassword=qs("#newPassword").value;
  const confirmPassword=qs("#confirmPassword").value;

  if(!currentPassword){ message.textContent="请输入当前密码"; message.className="form-message error"; return; }
  if(newPassword!==confirmPassword){ message.textContent="两次输入的新密码不一致"; message.className="form-message error"; return; }

  button.disabled=true; button.textContent="保存中…";
  message.textContent="";
  try{
    const data=await getJson("/api/settings/auth",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({username,current_password:currentPassword,new_password:newPassword,confirm_password:confirmPassword})
    });
    qs("#currentUser").textContent=data.username;
    qs("#settingsUsername").value=data.username;
    qs("#currentPassword").value="";
    qs("#newPassword").value="";
    qs("#confirmPassword").value="";
    qs("#authSource").textContent="面板持久化";
    message.textContent="已保存，新的用户名/密码立即生效";
    message.className="form-message ok";
  }catch(e){
    message.textContent=e.message;
    message.className="form-message error";
  }finally{
    button.disabled=false; button.textContent="保存账号设置";
  }
}

async function loadLogs(){
  try{
    const l=await getJson("/api/logs");
    qs("#logBox").textContent=l.items.map(x=>"["+x.time+"] "+x.level+"  "+x.message).join("\n");
  }catch(e){qs("#logBox").textContent="日志读取失败"; }
}

async function loadAll(){
  await Promise.all([loadMe(),loadStatus(),loadOpenVPN(),loadSettings(),loadLogs(),loadNodes(false)]);
}

const initial=location.hash.replace("#","")||"dashboard";
if(pageMeta[initial]) showPage(initial);
loadAll();
