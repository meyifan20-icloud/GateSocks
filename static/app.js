const pageMeta = {
  dashboard:["仪表盘","查看 GateSocks 当前运行状态与出口概况"],
  nodes:["节点池","筛选、测试并选择真实可用的候选出口"],
  socks:["SOCKS5","管理已生成的本地与外部 SOCKS5 访问地址"],
  openvpn:["OpenVPN","查看 SOCKS5 背后的 OpenVPN 隧道状态"],
  tests:["测试记录","查看延迟、速度、稳定性与出口检测历史"],
  logs:["日志","查看 GateSocks 当前运行日志"],
  settings:["设置","查看 Web 服务与端口规划"]
};

const qs = s => document.querySelector(s);
const qsa = s => [...document.querySelectorAll(s)];

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
qs("#reloadLogs").onclick=()=>loadLogs();\nqs("#logoutBtn").onclick=async()=>{ await fetch("/api/logout",{method:"POST"}); location.replace("/login"); };

function kv(label,value){
  const box=document.createElement("div"); box.className="kv";
  const s=document.createElement("span"); s.textContent=label;
  const b=document.createElement("strong"); b.textContent=value;
  box.append(s,b); return box;
}

async function getJson(url){
  const r=await fetch(url,{cache:"no-store"});
  if(!r.ok) throw new Error(url+" "+r.status);
  return r.json();
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
      d.innerHTML='<div class="proxy-head"><div><strong>'+t.name+'</strong><span>OpenVPN/TUN interface</span></div><span class="pill ok">'+t.state+'</span></div>';
      list.appendChild(d);
    });
  }catch(e){}
}

async function loadSettings(){
  try{
    const s=await getJson("/api/settings");
    qs("#webBind").value=s.web.bind;
    qs("#webPort").value=s.web.port;
  }catch(e){}
}

async function loadLogs(){
  try{
    const l=await getJson("/api/logs");
    qs("#logBox").textContent=l.items.map(x=>"["+x.time+"] "+x.level+"  "+x.message).join("\n");
  }catch(e){qs("#logBox").textContent="日志读取失败"; }
}

async function loadAll(){
  await Promise.all([loadStatus(),loadOpenVPN(),loadSettings(),loadLogs()]);
}
const initial=location.hash.replace("#","")||"dashboard";
if(pageMeta[initial]) showPage(initial);
loadAll();
