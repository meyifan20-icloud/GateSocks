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
let testPollTimer=null;

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

const startFilterBtn=qs("#startFilterBtn");
if(startFilterBtn) startFilterBtn.onclick=startRealTests;

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
  return {candidate:"候选",available:"实测通过",testing:"测试中",unavailable:"本次实测失败"}[value]||value||"-";
}

function filteredNodes(){
  const country=(qs("#countryFilter")?.value||"").toUpperCase();
  const status=qs("#nodeStatusFilter")?.value||"";
  const search=(qs("#nodeSearch")?.value||"").trim().toLowerCase();
  return allNodes.filter(n=>{
    if(country && n.country_short!==country) return false;
    if(status && n.status!==status) return false;
    if(search){
      const hay=[n.ip,n.hostname,n.country_short,n.country_long,n.operator,n.isp,n.asn,n.exit_ip].join(" ").toLowerCase();
      if(!hay.includes(search)) return false;
    }
    return true;
  });
}

function fmt(value,suffix=""){
  return value===null||value===undefined||value===""?"-":String(value)+suffix;
}

function renderNodes(){
  const table=qs("#nodesTable");
  if(!table) return;
  const items=filteredNodes();
  table.innerHTML="";
  if(!items.length){
    const tr=document.createElement("tr");
    const td=document.createElement("td"); td.colSpan=11;
    const empty=document.createElement("div"); empty.className="empty compact"; empty.textContent="没有符合当前筛选条件的节点";
    td.appendChild(empty); tr.appendChild(td); table.appendChild(tr); return;
  }
  items.forEach(n=>{
    const tr=document.createElement("tr");
    if(n.test_error) tr.title=n.test_error;
    const values=[
      n.country_short||"-",
      n.exit_ip?(n.ip+" → "+n.exit_ip):(n.ip||"-"),
      [n.isp,n.asn].filter(Boolean).join(" / ")||"待实测",
      n.residential_hint||"待实测",
      n.latency_ms!=null?fmt(n.latency_ms," ms"):n.source_ping_ms==null?"-":fmt(n.source_ping_ms," ms*"),
      n.download_mbps!=null?fmt(n.download_mbps," Mbps"):n.source_speed_mbps==null?"-":fmt(n.source_speed_mbps," Mbps*"),
      n.upload_mbps!=null?fmt(n.upload_mbps," Mbps"):"-",
      n.stability_percent!=null?fmt(n.stability_percent,"%"):"-",
      n.risk||"待实测",
      statusText(n.status)
    ];
    values.forEach(value=>{const td=document.createElement("td"); td.textContent=value; tr.appendChild(td);});
    const action=document.createElement("td");
    const button=document.createElement("button");
    button.className=n.selected?"btn primary":"btn ghost";
    button.disabled=false;
    button.textContent=n.selected?"已选择":"选择";
    button.onclick=()=>selectNode(n.id);
    if(n.selected) tr.classList.add("selected-row");
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
    if(meta) meta.textContent="来源："+(data.source||"VPN Gate")+" · 候选 "+count+" 个 · 更新："+updated+" · * 为公益源公布值，未标 * 的字段来自本 VPS 实测";
    if(qs("#statNodes")) qs("#statNodes").textContent=count;
    if(startFilterBtn) startFilterBtn.disabled=!allNodes.length;
  }catch(e){
    allNodes=[];
    renderNodes();
    if(meta) meta.textContent="节点池读取失败："+e.message;
    if(startFilterBtn) startFilterBtn.disabled=true;
  }finally{
    if(button){button.disabled=false;button.textContent="拉取节点";}
  }
}

async function selectNode(nodeId){
  const meta=qs("#testJobMeta");
  try{
    const data=await getJson("/api/nodes/select",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({node_id:nodeId})
    });
    allNodes=allNodes.map(n=>({...n,selected:n.id===nodeId}));
    renderNodes();
    await loadSelectedNode();
    if(meta) meta.textContent=data.message||"节点已选择";
  }catch(e){
    if(meta) meta.textContent="选择节点失败："+e.message;
  }
}

async function loadSelectedNode(){
  const box=qs("#selectedNodeCard");
  if(!box) return;
  try{
    const data=await getJson("/api/nodes/selected");
    const n=data.selected;
    if(!n){box.className="empty";box.textContent="当前还没有选择节点。";return;}
    box.className="selected-summary";
    box.innerHTML="";
    const title=document.createElement("strong");
    title.textContent=(n.country_short||"-")+" · "+(n.ip||"-");
    const detail=document.createElement("span");
    const parts=[];
    if(n.exit_ip) parts.push("出口 "+n.exit_ip);
    if(n.status) parts.push(statusText(n.status));
    parts.push("测试结果不限制选择");
    detail.textContent=parts.join(" · ");
    const clear=document.createElement("button");
    clear.className="btn ghost"; clear.textContent="取消选择";
    clear.onclick=async()=>{
      await getJson("/api/nodes/selected",{method:"DELETE"});
      allNodes=allNodes.map(x=>({...x,selected:false}));
      renderNodes();
      await loadSelectedNode();
    };
    box.append(title,detail,clear);
  }catch(e){
    box.className="empty";box.textContent="当前选择节点读取失败";
  }
}

async function loadDataSources(){
  const box=qs("#sourceInfo");
  if(!box) return;
  try{
    const s=await getJson("/api/data-sources");
    box.innerHTML="";
    const entries=[
      ["候选/源数据",s.candidate],
      ["真实出口 IP",s.exit_ip],
      ["实测吞吐",s.throughput],
      ["住宅/代理判断",s.ip_intel]
    ];
    entries.forEach(([label,src])=>{
      const card=document.createElement("div"); card.className="source-card";
      const h=document.createElement("strong"); h.textContent=label+" · "+src.name;
      const p=document.createElement("p"); p.textContent=src.purpose||"";
      card.append(h,p);
      const url=src.url||(src.urls&&src.urls[0]);
      if(url){
        const a=document.createElement("a"); a.href=url; a.target="_blank"; a.rel="noopener noreferrer"; a.textContent="查看来源";
        card.appendChild(a);
      }
      if(src.fields){
        const f=document.createElement("small"); f.textContent="使用字段："+src.fields.join(" / "); card.appendChild(f);
      }
      if(src.rules){
        const ul=document.createElement("ul");
        src.rules.forEach(rule=>{const li=document.createElement("li");li.textContent=rule;ul.appendChild(li);});
        card.appendChild(ul);
      }
      box.appendChild(card);
    });
  }catch(e){
    box.innerHTML='<div class="empty compact">数据源说明读取失败</div>';
  }
}

async function startRealTests(){
  const visible=filteredNodes().filter(n=>n.status!=="testing");
  const meta=qs("#testJobMeta");
  if(!visible.length){if(meta) meta.textContent="当前筛选条件下没有可测试节点。";return;}
  const ids=visible.slice(0,5).map(n=>n.id);
  startFilterBtn.disabled=true; startFilterBtn.textContent="启动中…";
  try{
    const data=await getJson("/api/tests/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids,limit:5})});
    if(meta) meta.textContent="实测已启动："+data.total+" 个节点。单节点会建立临时 OpenVPN 隧道并测试出口、延迟、上下行与稳定性。";
    beginTestPolling();
  }catch(e){
    if(meta) meta.textContent="实测启动失败："+e.message;
    startFilterBtn.disabled=false; startFilterBtn.textContent="开始实测筛选";
  }
}

function beginTestPolling(){
  if(testPollTimer) clearInterval(testPollTimer);
  pollTestJob();
  testPollTimer=setInterval(pollTestJob,2500);
}

async function pollTestJob(){
  try{
    const job=await getJson("/api/tests/status");
    const meta=qs("#testJobMeta");
    if(job.running){
      if(startFilterBtn){startFilterBtn.disabled=true;startFilterBtn.textContent="实测中 "+job.completed+"/"+job.total;}
      if(meta) meta.textContent="实测进行中："+job.completed+"/"+job.total+(job.current_id?" · 当前 "+job.current_id:"")+"。测试期间 Web 面板流量不会切入临时 VPN。";
    }else{
      if(startFilterBtn){startFilterBtn.disabled=!allNodes.length;startFilterBtn.textContent="开始实测筛选";}
      if(job.total){
        if(meta) meta.textContent="最近实测完成："+job.completed+"/"+job.total+(job.last_error?" · 最近失败原因："+job.last_error:"");
        await Promise.all([loadNodes(false),loadTests()]);
      }
      if(testPollTimer){clearInterval(testPollTimer);testPollTimer=null;}
    }
  }catch(e){
    if(testPollTimer){clearInterval(testPollTimer);testPollTimer=null;}
    if(startFilterBtn){startFilterBtn.disabled=false;startFilterBtn.textContent="开始实测筛选";}
  }
}

async function loadTests(){
  const list=qs("#testsList");
  if(!list) return;
  try{
    const data=await getJson("/api/tests");
    const items=data.items||[];
    list.innerHTML="";
    if(!items.length){list.innerHTML="<div class=\"empty\">暂无真实连接测试记录</div>";return;}
    items.slice(0,50).forEach(t=>{
      const card=document.createElement("div"); card.className="proxy-card";
      const head=document.createElement("div"); head.className="proxy-head";
      const left=document.createElement("div");
      const strong=document.createElement("strong"); strong.textContent=(t.country_short||"-")+" · "+(t.source_ip||"-");
      const span=document.createElement("span"); span.textContent=t.tested_at?new Date(t.tested_at).toLocaleString():"";
      left.append(strong,span);
      const state=document.createElement("span"); state.className="pill "+(t.status==="available"?"ok":""); state.textContent=statusText(t.status);
      head.append(left,state);
      const grid=document.createElement("div"); grid.className="mini-grid";
      [["出口 IP",t.exit_ip||"-"],["延迟",t.latency_ms==null?"-":t.latency_ms+" ms"],["下载",t.download_mbps==null?"-":t.download_mbps+" Mbps"],["上传",t.upload_mbps==null?"-":t.upload_mbps+" Mbps"],["短时成功率",t.stability_percent==null?"-":t.stability_percent+"%"],["住宅/风险",(t.residential_hint||"未知")+" / "+(t.risk||"未知")]].forEach(([a,b])=>{const d=document.createElement("div");const s=document.createElement("span");s.textContent=a;const v=document.createElement("strong");v.textContent=b;d.append(s,v);grid.appendChild(d);});
      card.append(head,grid);
      const evidence=document.createElement("details"); evidence.className="evidence";
      const summary=document.createElement("summary"); summary.textContent="查看测试数据来源与住宅判据";
      evidence.appendChild(summary);
      const ev=t.evidence||{};
      const flags=ev.ip_intel_fields||{};
      const lines=[
        "候选/源 Ping/源线路速度："+(ev.candidate_source||"VPN Gate"),
        "真实出口 IP："+(ev.exit_ip_source||"旧记录未保存具体来源"),
        "下载/上传实测："+(ev.speed_source||"Cloudflare speed.cloudflare.com"),
        "住宅/代理判断："+(ev.ip_intel_source||"ip-api.com"),
        "ip-api 判据：hosting="+String(flags.hosting)+" · proxy="+String(flags.proxy)+" · mobile="+String(flags.mobile),
        "说明：住宅判断只是公开数据库信号；false 不等于已经证明是住宅 IP。"
      ];
      lines.forEach(line=>{const p=document.createElement("p");p.textContent=line;evidence.appendChild(p);});
      card.appendChild(evidence);
      if(t.error){const err=document.createElement("p");err.className="form-message error";err.textContent=t.error;card.appendChild(err);}
      list.appendChild(card);
    });
  }catch(e){list.innerHTML="<div class=\"empty\">测试记录读取失败</div>";}
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
  await Promise.all([loadMe(),loadStatus(),loadOpenVPN(),loadSettings(),loadLogs(),loadNodes(false),loadTests(),loadSelectedNode(),loadDataSources()]);
  pollTestJob();
}

const initial=location.hash.replace("#","")||"dashboard";
if(pageMeta[initial]) showPage(initial);
loadAll();
