const pageMeta = {
  dashboard:["仪表盘","查看 GateSocks 当前运行状态与出口概况"],
  nodes:["节点池","筛选、测试并选择真实可用的候选出口"],
  socks:["SOCKS5","选择待生成节点并管理已经生成的 SOCKS5 实例"],
  openvpn:["OpenVPN","查看 SOCKS5 背后的 OpenVPN 隧道状态"],
  tests:["测试记录","查看延迟、速度、稳定性与出口检测历史"],
  logs:["日志","查看 GateSocks 当前运行日志"],
  settings:["设置","查看服务参数并管理管理员账号"]
};

const qs = s => document.querySelector(s);
const qsa = s => [...document.querySelectorAll(s)];
let allNodes=[];
let testSelectedIds=new Set();
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

const selectAllTestsBtn=qs("#selectAllTestsBtn");
if(selectAllTestsBtn) selectAllTestsBtn.onclick=selectAllVisibleForTest;

const clearTestSelectionBtn=qs("#clearTestSelectionBtn");
if(clearTestSelectionBtn) clearTestSelectionBtn.onclick=clearTestSelection;

["#countryFilter","#nodeStatusFilter","#nodeSearch"].forEach(sel=>{
  const el=qs(sel);
  if(el) el.addEventListener(sel==="#nodeSearch"?"input":"change",renderNodes);
});

const saveAuthBtn=qs("#saveAuthBtn");
if(saveAuthBtn) saveAuthBtn.onclick=saveAuthSettings;

let qrObjectUrl=null;
const qrModal=qs("#qrModal");
const qrCloseBtn=qs("#qrCloseBtn");
if(qrCloseBtn) qrCloseBtn.onclick=closeQr;
if(qrModal) qrModal.addEventListener("click",e=>{if(e.target===qrModal) closeQr();});
document.addEventListener("keydown",e=>{if(e.key==="Escape" && qrModal && !qrModal.hidden) closeQr();});

function closeQr(){
  if(qrObjectUrl){URL.revokeObjectURL(qrObjectUrl);qrObjectUrl=null;}
  if(qrModal) qrModal.hidden=true;
  const img=qs("#qrImage");
  if(img){img.removeAttribute("src");img.hidden=false;}
}

function showQrError(message,label="代理信息"){
  if(qrObjectUrl){URL.revokeObjectURL(qrObjectUrl);qrObjectUrl=null;}
  const img=qs("#qrImage");
  if(img){img.removeAttribute("src");img.hidden=true;}
  qs("#qrTitle").textContent="二维码生成失败";
  qs("#qrSubtitle").textContent=label;
  qs("#qrText").textContent=message||"二维码生成失败";
  qrModal.hidden=false;
}

async function showQr(text,label="代理信息"){
  if(!text) throw new Error("二维码内容为空");
  const r=await fetch("/api/qr",{
    method:"POST",
    cache:"no-store",
    headers:{"Content-Type":"application/json"},
    body:JSON.stringify({text})
  });
  if(r.status===401){location.replace("/login");return;}
  if(!r.ok){
    const data=await r.json().catch(()=>({}));
    throw new Error(data.detail||("二维码生成失败（HTTP "+r.status+"）"));
  }
  const contentType=(r.headers.get("content-type")||"").toLowerCase();
  if(!contentType.includes("image/svg+xml")) throw new Error("二维码接口返回了无效内容");
  const blob=await r.blob();
  if(qrObjectUrl) URL.revokeObjectURL(qrObjectUrl);
  qrObjectUrl=URL.createObjectURL(blob);
  const img=qs("#qrImage");
  img.hidden=false;
  img.src=qrObjectUrl;
  qs("#qrTitle").textContent=label;
  qs("#qrSubtitle").textContent=label==="完整地址"?"可供支持 SOCKS5 URI 的移动代理客户端扫码添加":"扫码读取该字段文本";
  qs("#qrText").textContent=text;
  qrModal.hidden=false;
}

async function copyText(text,button){
  try{
    await navigator.clipboard.writeText(text);
    if(button){const old=button.textContent;button.textContent="已复制";setTimeout(()=>button.textContent=old,1200);}
  }catch(e){}
}

function appendAccessRow(container,label,value,enableQr=true){
  const row=document.createElement("div"); row.className="copy-row"+(enableQr?" qr-ready":"");
  const l=document.createElement("span"); l.textContent=label;
  const code=document.createElement("code"); code.textContent=value||"-";
  const copy=document.createElement("button"); copy.textContent="复制"; copy.disabled=!value; copy.onclick=()=>copyText(value,copy);
  row.append(l,code,copy);
  if(enableQr){
    const qr=document.createElement("button");
    qr.textContent="二维码";
    qr.disabled=!value;
    qr.onclick=async()=>{
      const old=qr.textContent;
      qr.disabled=true;
      qr.textContent="生成中…";
      try{await showQr(value,label);}
      catch(e){showQrError(e.message,label);}
      finally{qr.disabled=!value;qr.textContent=old;}
    };
    row.appendChild(qr);
  }
  container.appendChild(row);
  return row;
}

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

function updateTestSelectionUi(){
  const count=testSelectedIds.size;
  if(startFilterBtn){
    startFilterBtn.textContent="开始实测（"+count+"）";
    if(!testPollTimer) startFilterBtn.disabled=count===0;
  }
  const selectedCount=qs("#testSelectedCount");
  if(selectedCount) selectedCount.textContent=String(count);
}

function selectAllVisibleForTest(){
  filteredNodes().forEach(n=>testSelectedIds.add(n.id));
  renderNodes();
}

function clearTestSelection(){
  testSelectedIds.clear();
  renderNodes();
}

function toggleTestSelection(nodeId,checked){
  if(checked) testSelectedIds.add(nodeId);
  else testSelectedIds.delete(nodeId);
  updateTestSelectionUi();
}

function renderNodes(){
  const table=qs("#nodesTable");
  if(!table) return;
  const items=filteredNodes();
  table.innerHTML="";
  if(!items.length){
    const tr=document.createElement("tr");
    const td=document.createElement("td"); td.colSpan=13;
    const empty=document.createElement("div"); empty.className="empty compact"; empty.textContent="没有符合当前筛选条件的节点";
    td.appendChild(empty); tr.appendChild(td); table.appendChild(tr); updateTestSelectionUi(); return;
  }
  items.forEach(n=>{
    const tr=document.createElement("tr");
    if(n.test_error) tr.title=n.test_error;
    const checkTd=document.createElement("td"); checkTd.className="test-check-col";
    const checkbox=document.createElement("input"); checkbox.type="checkbox"; checkbox.className="test-checkbox"; checkbox.checked=testSelectedIds.has(n.id);
    checkbox.setAttribute("aria-label","选择 "+(n.ip||n.id)+" 进行实测"); checkbox.onchange=()=>toggleTestSelection(n.id,checkbox.checked);
    checkTd.appendChild(checkbox); tr.appendChild(checkTd);
    const countryTd=document.createElement("td"); countryTd.textContent=n.country_short||"-"; tr.appendChild(countryTd);
    const ipTd=document.createElement("td");
    const ipButton=document.createElement("button"); ipButton.type="button"; ipButton.className="ip-select-btn"+(n.selected?" selected":"");
    ipButton.title="点击设为仪表盘当前待生成节点（单选，不直接生效）"; ipButton.textContent=n.exit_ip?(n.ip+" → "+n.exit_ip):(n.ip||"-"); ipButton.onclick=()=>selectNode(n.id);
    ipTd.appendChild(ipButton);
    if(n.selected){const badge=document.createElement("span");badge.className="ip-selected-badge";badge.textContent="待生成";ipTd.appendChild(badge);tr.classList.add("selected-row");}
    tr.appendChild(ipTd);
    const values=[
      n.source_ping_ms==null?"-":fmt(n.source_ping_ms," ms*"),
      n.source_speed_mbps==null?"-":fmt(n.source_speed_mbps," Mbps*"),
      n.latency_ms!=null?fmt(n.latency_ms," ms"):"-",
      n.download_mbps!=null?fmt(n.download_mbps," Mbps"):"-",
      n.upload_mbps!=null?fmt(n.upload_mbps," Mbps"):"-",
      [n.isp,n.asn].filter(Boolean).join(" / ")||"待实测",
      n.residential_hint||"待实测",
      n.stability_percent!=null?fmt(n.stability_percent,"%"):"-",
      n.risk||"待实测",
      statusText(n.status)
    ];
    values.forEach(value=>{const td=document.createElement("td");td.textContent=value;tr.appendChild(td);});
    table.appendChild(tr);
  });
  updateTestSelectionUi();
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
    const liveIds=new Set(allNodes.map(n=>n.id));
    testSelectedIds=new Set([...testSelectedIds].filter(id=>liveIds.has(id)));
    fillCountryFilter();
    renderNodes();
    const count=data.count??allNodes.length;
    const updated=data.updated_at?new Date(data.updated_at).toLocaleString():"尚未缓存";
    if(meta) meta.textContent="候选源："+(data.source||"VPN Gate")+" · "+count+" 个 · 更新："+updated+" · “源 Ping* / 源线路速度*”仅来自公益项目；“实测延迟 / 实测下载 / 实测上传”仅来自本 VPS，不再相互回退混显";
    if(qs("#statNodes")) qs("#statNodes").textContent=count;
    updateTestSelectionUi();
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

async function createSocksFromSelected(nodeId,button,message){
  if(!nodeId) return;
  const old=button.textContent;
  button.disabled=true;
  button.textContent="生成中…";
  if(message){message.textContent="正在建立长期 OpenVPN 隧道并启动 SOCKS5，这一步可能需要几十秒。";message.className="form-message";}
  try{
    const data=await getJson("/api/socks",{
      method:"POST",
      headers:{"Content-Type":"application/json"},
      body:JSON.stringify({node_id:nodeId})
    });
    const item=data.instance||{};
    await Promise.all([loadSocks(),loadOpenVPN(),loadStatus()]);
    if(item.status==="online"){
      if(message){
        const connectHost=item.connect_host||item.host||"VPS";
        const vpnExit=item.vpn_exit_ip||item.exit_ip||"待确认";
        message.textContent="SOCKS5 已生成："+connectHost+":"+item.port+"；流量真实出口 "+vpnExit;
        message.className="form-message ok";
      }
      showPage("socks");
    }else{
      if(message){message.textContent="实例已建立记录，但启动失败："+(item.last_error||item.status||"未知错误");message.className="form-message error";}
    }
  }catch(e){
    if(message){message.textContent="生成 SOCKS5 失败："+e.message;message.className="form-message error";}
  }finally{
    button.disabled=false;
    button.textContent=old;
    await loadSelectedNode();
  }
}

async function loadSelectedNode(){
  const box=qs("#selectedNodeCard");
  if(!box) return;
  try{
    const data=await getJson("/api/nodes/selected");
    const n=data.selected;
    if(!n){box.className="empty";box.textContent="当前还没有待生成节点。请到节点池直接点击一个 IP。";return;}
    box.className="selected-summary";
    box.innerHTML="";
    const content=document.createElement("div");
    content.className="selected-content";
    const title=document.createElement("strong");
    title.textContent=(n.country_short||"-")+" · "+(n.ip||"-");
    const detail=document.createElement("span");
    const parts=[];
    if(n.exit_ip) parts.push("最近实测出口 "+n.exit_ip);
    if(n.status) parts.push(statusText(n.status));
    parts.push("待生成节点（单选，不直接生效）");
    detail.textContent=parts.join(" · ");
    const message=document.createElement("div");
    message.className="form-message";
    content.append(title,detail,message);

    const actions=document.createElement("div");
    actions.className="selected-actions";
    const generate=document.createElement("button");
    generate.className="btn primary";
    generate.textContent="生成并启用 SOCKS5";
    generate.onclick=()=>createSocksFromSelected(n.id||n.node_id,generate,message);
    const clear=document.createElement("button");
    clear.className="btn ghost";
    clear.textContent="取消待生成";
    clear.onclick=async()=>{
      await getJson("/api/nodes/selected",{method:"DELETE"});
      allNodes=allNodes.map(x=>({...x,selected:false}));
      renderNodes();
      await loadSelectedNode();
    };
    actions.append(generate,clear);
    box.append(content,actions);
  }catch(e){
    box.className="empty";box.textContent="待生成节点读取失败";
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
  const meta=qs("#testJobMeta");
  const ids=[...testSelectedIds];
  if(!ids.length){
    if(meta) meta.textContent="请先用每行最前面的复选框选择要测试的 IP，或点击“全选当前筛选”。";
    updateTestSelectionUi();
    return;
  }
  startFilterBtn.disabled=true; startFilterBtn.textContent="启动中…";
  try{
    const data=await getJson("/api/tests/start",{method:"POST",headers:{"Content-Type":"application/json"},body:JSON.stringify({ids})});
    if(meta) meta.textContent="实测已启动："+data.total+" 个手动选择节点。测试勾选与仪表盘当前使用节点互不影响。";
    beginTestPolling();
  }catch(e){
    if(meta) meta.textContent="实测启动失败："+e.message;
    updateTestSelectionUi();
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
      if(startFilterBtn){startFilterBtn.disabled=testSelectedIds.size===0;startFilterBtn.textContent="开始实测（"+testSelectedIds.size+"）";}
      if(job.total){
        if(meta) meta.textContent="最近实测完成："+job.completed+"/"+job.total+(job.last_error?" · 最近失败原因："+job.last_error:"");
        await Promise.all([loadNodes(false),loadTests()]);
      }
      if(testPollTimer){clearInterval(testPollTimer);testPollTimer=null;}
    }
  }catch(e){
    if(testPollTimer){clearInterval(testPollTimer);testPollTimer=null;}
    updateTestSelectionUi();
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
function socksStatusText(status){
  return {online:"在线",starting:"启动中",stopped:"已停止",error:"异常",created:"已创建"}[status]||status||"-";
}

function makeInstanceAction(label,className,handler){
  const b=document.createElement("button");
  b.className="btn "+(className||"ghost");
  b.textContent=label;
  b.onclick=handler;
  return b;
}

async function runInstanceAction(item,action,button){
  const old=button.textContent;
  button.disabled=true;
  button.textContent="处理中…";
  try{
    await getJson("/api/socks/"+encodeURIComponent(item.id)+"/"+action,{method:"POST"});
  }catch(e){
    alert(e.message);
  }finally{
    button.disabled=false;
    button.textContent=old;
    await Promise.all([loadSocks(),loadOpenVPN(),loadStatus()]);
  }
}

async function deleteInstance(item,button){
  const ok=confirm("确认删除 "+(item.name||item.id)+"？\n\n这会停止对应 SOCKS5 与 OpenVPN、清理策略路由、删除实例配置并释放端口 "+item.port+"。\n节点池和历史测试记录不会删除。");
  if(!ok) return;
  const old=button.textContent;
  button.disabled=true;
  button.textContent="删除中…";
  try{
    await getJson("/api/socks/"+encodeURIComponent(item.id),{method:"DELETE"});
  }catch(e){
    alert(e.message);
  }finally{
    button.disabled=false;
    button.textContent=old;
    await Promise.all([loadSocks(),loadOpenVPN(),loadStatus()]);
  }
}

function appendMetric(grid,label,value){
  const d=document.createElement("div");
  const s=document.createElement("span"); s.textContent=label;
  const v=document.createElement("strong"); v.textContent=value||"-";
  d.append(s,v); grid.appendChild(d);
}

async function loadSocks(){
  const list=qs("#socksList");
  if(!list) return;
  try{
    const data=await getJson("/api/socks");
    const items=data.items||[];
    if(!items.length){
      list.innerHTML='<div class="empty">尚未生成 SOCKS5 实例。先到节点池点击一个 IP，再回到本页顶部从“当前待生成节点”生成。</div>';
      return;
    }
    list.innerHTML="";
    items.forEach((item,index)=>{
      const card=document.createElement("div"); card.className="proxy-card";
      const head=document.createElement("div"); head.className="proxy-head";
      const left=document.createElement("div");
      const title=document.createElement("strong"); title.textContent=item.name||("SOCKS5-"+(index+1));
      const sub=document.createElement("span");
      sub.textContent=(item.country_short||"-")+" · 接入 "+(item.source_ip||"-")+" · 端口 "+item.port;
      left.append(title,sub);
      const state=document.createElement("span");
      state.className="pill "+(item.status==="online"?"ok":item.status==="error"?"error":item.status==="starting"?"warn":"");
      state.textContent=socksStatusText(item.status);
      head.append(left,state); card.appendChild(head);

      const grid=document.createElement("div"); grid.className="mini-grid";
      appendMetric(grid,"VPN Gate 接入节点",item.vpn_source_ip||item.source_ip||"-");
      appendMetric(grid,"SOCKS5 真实出口",item.vpn_exit_ip||item.exit_ip||"-");
      appendMetric(grid,"ISP / ASN",[item.isp,item.asn].filter(Boolean).join(" / ")||"-");
      appendMetric(grid,"OpenVPN / TUN",item.tun_name||"-");
      const probe=item.last_probe||{};
      appendMetric(grid,"最近实测",probe.tested_at?new Date(probe.tested_at).toLocaleString():"-");
      appendMetric(grid,"实测速度",probe.download_mbps!=null?(probe.download_mbps+"↓ / "+(probe.upload_mbps??"-")+"↑ Mbps"):"-");
      card.appendChild(grid);

      const accessGrid=document.createElement("div"); accessGrid.className="access-grid";
      const local=document.createElement("div"); local.className="access-box";
      const lh=document.createElement("h3"); lh.textContent="本地访问";
      const ln=document.createElement("p"); ln.className="access-note"; ln.textContent="VPS 本机使用；停止实例后该端口不再监听。";
      local.append(lh,ln);
      appendAccessRow(local,"地址",item.local_host||"127.0.0.1",false);
      appendAccessRow(local,"端口",item.port?String(item.port):"",false);
      appendAccessRow(local,"用户名",item.username||"",false);
      appendAccessRow(local,"密码",item.password||"",false);
      appendAccessRow(local,"完整地址",item.local_uri||"",false);

      const external=document.createElement("div"); external.className="access-box";
      const eh=document.createElement("h3"); eh.textContent="外部访问";
      const en=document.createElement("p"); en.className="access-note";
      const connectHost=item.connect_host||item.host||"";
      const vpnSource=item.vpn_source_ip||item.source_ip||"";
      const vpnExit=item.vpn_exit_ip||item.exit_ip||"";
      en.textContent=connectHost
        ?"客户端连接的是 GateSocks VPS；服务器地址固定为本 VPS 公网 IP。所选 VPN Gate 节点只负责上游隧道，流量从“真实出口 IP”出站。"
        :"未自动识别 VPS 公网地址；可通过 GATESOCKS_PUBLIC_HOST 指定后再使用外部访问。";
      external.append(eh,en);
      appendAccessRow(external,"SOCKS5 服务器（VPS）",connectHost,true);
      appendAccessRow(external,"服务端口",item.port?String(item.port):"",true);
      appendAccessRow(external,"VPN Gate 接入节点",vpnSource,false);
      appendAccessRow(external,"真实出口 IP",vpnExit,false);
      appendAccessRow(external,"用户名",item.username||"",true);
      appendAccessRow(external,"密码",item.password||"",true);
      appendAccessRow(external,"客户端导入地址",item.url||"",true);
      accessGrid.append(local,external);
      card.appendChild(accessGrid);

      if(item.last_error){
        const err=document.createElement("p");
        err.className="instance-error";
        err.textContent="最近错误："+item.last_error;
        card.appendChild(err);
      }

      const actions=document.createElement("div"); actions.className="instance-actions";
      if(item.status==="online"||item.status==="starting"){
        const stop=makeInstanceAction("停止","ghost",()=>runInstanceAction(item,"stop",stop));
        actions.appendChild(stop);
      }else{
        const start=makeInstanceAction("启动","primary",()=>runInstanceAction(item,"start",start));
        actions.appendChild(start);
      }
      const reconnect=makeInstanceAction("重新连接","ghost",()=>runInstanceAction(item,"reconnect",reconnect));
      actions.appendChild(reconnect);
      if(item.status==="online"){
        const retest=makeInstanceAction("重新测试","ghost",()=>runInstanceAction(item,"test",retest));
        actions.appendChild(retest);
      }
      const del=makeInstanceAction("删除实例","danger",()=>deleteInstance(item,del));
      actions.appendChild(del);
      card.appendChild(actions);
      list.appendChild(card);
    });
  }catch(e){
    list.innerHTML='<div class="empty">SOCKS5 信息读取失败：'+e.message+'</div>';
  }
}

async function loadOpenVPN(){
  try{
    const o=await getJson("/api/openvpn");
    const info=qs("#openvpnInfo"); info.innerHTML="";
    [["OpenVPN",o.version],["TUN 设备",o.tun_present?"可用":"不可用"],["正式实例隧道",o.instance_count],["临时测试隧道",o.test_count],["其他 TUN/TAP",o.other_count]].forEach(([a,b])=>info.appendChild(kv(a,b)));
    qs("#tunBadge").textContent=o.tun_present?"TUN 可用":"TUN 不可用";
    qs("#tunBadge").className="pill "+(o.tun_present?"ok":"");
    const list=qs("#tunnelList"); list.innerHTML="";
    if(!o.tunnels.length){ list.innerHTML='<div class="empty">当前没有活动的 TUN/TAP 隧道</div>'; return; }
    o.tunnels.forEach(t=>{
      const d=document.createElement("div"); d.className="proxy-card";
      const head=document.createElement("div"); head.className="proxy-head";
      const left=document.createElement("div");
      const strong=document.createElement("strong"); strong.textContent=t.name;
      const span=document.createElement("span"); span.textContent=t.kind==="instance"?"正式 SOCKS5 出口":t.kind==="test"?"临时节点测试":"其他 TUN/TAP";
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
    const socksPool=s.socks_port_pool.start+"–"+s.socks_port_pool.end;
    const testPool=s.test_port_pool.start+"–"+s.test_port_pool.end;
    if(qs("#dashboardSocksPool")) qs("#dashboardSocksPool").textContent=socksPool;
    if(qs("#dashboardTestPool")) qs("#dashboardTestPool").textContent=testPool;
    if(qs("#settingsSocksPool")) qs("#settingsSocksPool").value=s.socks_port_pool.start+"-"+s.socks_port_pool.end;
    if(qs("#settingsTestPool")) qs("#settingsTestPool").value=s.test_port_pool.start+"-"+s.test_port_pool.end;
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
  await Promise.all([loadMe(),loadStatus(),loadOpenVPN(),loadSocks(),loadSettings(),loadLogs(),loadNodes(false),loadTests(),loadSelectedNode(),loadDataSources()]);
  pollTestJob();
}

const initial=location.hash.replace("#","")||"dashboard";
if(pageMeta[initial]) showPage(initial);
loadAll();
