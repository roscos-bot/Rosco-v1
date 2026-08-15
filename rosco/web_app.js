"use strict";
var CSRF="", TYPEC={agent:"#c9a227",person:"#5b8fb0",site:"#4ea86e",tool:"#37b0a0",file:"#9a86c4",core:"#e8efeb"};

// The session lives only in the server's memory (the passphrase never touches
// disk, by design), so every server restart - including the auto-reload on a
// code change - silently invalidates an unlocked tab. Without this, the next
// write just returned "locked" in a result box with no way forward. Now any
// post-unlock 401/403 bounces straight back to the lock screen to re-unlock.
function relock(msg){
  CSRF="";
  var app=document.getElementById("app"),lock=document.getElementById("lock"),err=document.getElementById("err");
  if(app)app.style.display="none";
  if(lock)lock.style.display="flex";
  if(err)err.textContent=msg||"Session ended — unlock to continue.";
  var pw=document.getElementById("pw");if(pw){pw.value="";pw.focus();}
}
function guard(r){ if(CSRF&&(r.status===401||r.status===403))
  relock("Session ended (server restarted). Unlock to continue."); return r; }
function api(path){return fetch(path,{headers:{"Accept":"application/json"}}).then(guard).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j,status:r.status};});});}
function post(path,body){return fetch(path,{method:"POST",headers:{"Content-Type":"application/json","X-Rosco-CSRF":CSRF},body:JSON.stringify(body||{})}).then(guard).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j,status:r.status};});});}

// ---- unlock ----
function doUnlock(){
  var pw=document.getElementById("pw").value, err=document.getElementById("err");
  err.textContent="";
  post("/api/unlock",{passphrase:pw}).then(function(res){
    if(!res.ok){err.textContent=(res.j&&res.j.error)||"locked";return;}
    CSRF=res.j.csrf;
    document.getElementById("lock").style.display="none";
    document.getElementById("app").style.display="flex";
    boot();
  }).catch(function(){err.textContent="server unreachable";});
}
document.getElementById("unlock").addEventListener("click",doUnlock);
document.getElementById("pw").addEventListener("keydown",function(e){if(e.key==="Enter")doUnlock();});

// A still-valid session cookie (page reloaded, server never restarted) should
// walk straight in: recover the CSRF token from overview and boot, instead of
// stranding on the lock screen where the graph never builds.
api("/api/overview").then(function(res){
  if(res.ok&&res.j&&res.j.unlocked&&res.j.csrf){
    CSRF=res.j.csrf;
    document.getElementById("lock").style.display="none";
    document.getElementById("app").style.display="flex";
    boot();
  }
});

// ---- boot the live console ----
var seenAct={}, actFirst=true;
var booted=false;
function boot(){ resize(); requestAnimationFrame(resize);   // app is visible now: size the canvas
  refreshHud(); loadQueue(); loadMesh(); pollIngestPip();
  if(booted)return; booted=true;                            // re-unlock must not stack a 2nd set of timers
  setInterval(refreshHud,8000); setInterval(loadQueue,15000);
  setInterval(loadActivity,4000); setTimeout(loadActivity,1200);
  setInterval(pollIngestPip,20000); }

// Fire a light into every node that just DID something. On the first poll we
// only mark events seen (no burst of history); after that each new one flares.
function loadActivity(){ api("/api/activity").then(function(res){
  var a=(res.ok&&Array.isArray(res.j))?res.j:[];   // locked/old server -> skip
  var rosco=byId["Rosco"];
  a.forEach(function(ev){ if(seenAct[ev.id]) return; seenAct[ev.id]=1;
    if(actFirst) return;
    var to=byId[ev.node]; if(to==null) return;
    if(rosco!=null && rosco!==to) signals.push({from:rosco,to:to,t:0,sp:.02});
    if(N[to]) N[to].pulse=1;
    var su=document.querySelector(".netcap .su");
    if(su) su.innerHTML="<span style='color:var(--teal)'>● "+esc(ev.node)+" "+esc(ev.what)+"</span>";
  });
  actFirst=false;
});}

function refreshHud(){ api("/api/overview").then(function(res){var o=res.j;if(!res.ok||!o||!o.unlocked)return;
  document.getElementById("hud").innerHTML=
    stat("Waiting","<span class='dot "+(o.waiting?"a":"g")+"'></span>"+o.waiting)+
    stat("Spend","$"+o.spend.toFixed(2))+
    stat("Chains","<span class='dot "+(o.chains==="sound"?"g":"a")+"'></span>"+o.chains);
});}
function stat(k,v){return "<div class='stat'><span class='k'>"+k+"</span><span class='v'>"+v+"</span></div>";}

// ---- the queue ----
var SENS={"bound-book":1,"books":1,"payroll":1,"taxes":1,"transfers":1,"budget":1};
var ingCount=0;                          // pending ingest items, kept fresh by the pip poll
function ingestBanner(){
  return ingCount>0 ? "<div class='ask ingbanner' style='cursor:pointer;border-left:3px solid var(--teal)'>"
    +"<div class='said'>\U0001f4e5 <b>"+ingCount+"</b> item(s) in the ingest queue — click to review</div></div>" : "";
}
function loadQueue(){ api("/api/queue").then(function(res){
  var q=(res.ok&&Array.isArray(res.j))?res.j:[];
  markWaiting(q);                       // ring captains even while a node is shown
  var el=document.getElementById("qwrap"),rh=document.getElementById("rhead");
  if(!el||!rh) return;                  // a node's context is showing; queue is hidden
  rh.textContent="Waiting on you · "+q.length;
  el.innerHTML=(q.length?q.map(askCard).join(""):"<div class='empty'>Nothing waiting. You're clear.</div>")+ingestBanner();
  q.forEach(function(a){ wireCard(a.id); });
  var ib=el.querySelector(".ingbanner"); if(ib)ib.addEventListener("click",openIngest);
});}

// Ring the captain of any business with a request waiting on Ross. The captain
// is the agent node for that business that reports to Rosco.
function markWaiting(q){
  var wanted={}; q.forEach(function(a){ wanted[a.business]=1; });
  N.forEach(function(n){
    n.waiting = (n.type==="agent" && n.reports==="Rosco" && wanted[n.business]) ? 1 : 0;
  });
}
function esc(s){return (s==null?"":""+s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
function askCard(a){
  var sens=SENS[a.capability];
  return "<div class='ask"+(sens?" sens":"")+"' data-id='"+esc(a.id)+"'>"
    +"<div class='top'><span class='who'>"+esc(a.person)+"</span>"
    +"<span class='cap'>"+esc(a.business)+":"+esc(a.capability)+"</span>"
    +"<span class='verb"+(a.verb==="do"?" do":"")+"'>"+esc((a.verb||"").toUpperCase())+"</span>"
    +(sens?"<span class='verb' style='color:var(--red);border-color:var(--red-dim)'>SENSITIVE</span>":"")+"</div>"
    +"<div class='said'>"+esc(a.detail)+"</div>"
    +"<div class='acts'>"
    +"<button class='btn ga' data-v='allow-once'>Allow once</button>"
    +"<button class='btn ga solid' data-v='allow-always'>Allow always</button>"
    +"<button class='btn da' data-v='deny-once'>Deny once</button>"
    +"<button class='btn da solid' data-v='deny-always'>Deny always</button>"
    +"</div><div class='verdict' style='display:none'></div></div>";
}
function wireCard(id){
  var card=document.querySelector(".ask[data-id='"+id+"']"); if(!card)return;
  card.querySelectorAll(".btn").forEach(function(b){ b.addEventListener("click",function(){
    var v=b.getAttribute("data-v");
    card.querySelectorAll(".btn").forEach(function(x){x.disabled=true;});
    post("/api/answer",{id:id,verdict:v}).then(function(res){
      var vd=card.querySelector(".verdict"); vd.style.display="block";
      if(res.ok){var allow=v.indexOf("allow")===0;vd.className="verdict "+(allow?"a":"d");
        vd.textContent=(allow?"✓ ":"✗ ")+v.replace("-"," ").toUpperCase();
        setTimeout(function(){loadQueue();refreshHud();},700);}
      else{vd.className="verdict d";vd.textContent=(res.j&&res.j.error)||"failed";
        card.querySelectorAll(".btn").forEach(function(x){x.disabled=false;});}
    });
  });});
}

// ---- the mesh: force-directed 3D, star + fiber ----
var reduce=window.matchMedia&&window.matchMedia("(prefers-reduced-motion:reduce)").matches;
var N=[],E=[],byId={},sprite={},signals=[];
function makeSprite(col){var s=64,c=document.createElement("canvas");c.width=c.height=s;var g=c.getContext("2d");
  var rg=g.createRadialGradient(s/2,s/2,0,s/2,s/2,s/2);rg.addColorStop(0,col);rg.addColorStop(.25,col);rg.addColorStop(1,"rgba(0,0,0,0)");
  g.fillStyle=rg;g.fillRect(0,0,s,s);return c;}
Object.keys(TYPEC).forEach(function(k){sprite[k]=makeSprite(TYPEC[k]);});

function loadMesh(retry){ api("/api/mesh").then(function(res){
  var m=(res.ok&&res.j&&res.j.nodes)?res.j:{nodes:[],edges:[]};
  if(!m.nodes.length&&!retry){setTimeout(function(){loadMesh(true);},800);return;} // transient empty -> one retry
  byId={};N=m.nodes.map(function(n,i){byId[n.id]=i;
    return {id:n.id,label:n.label,type:n.type,rank:n.rank,biz:n.business,reports:n.reports,
      x:(Math.random()-.5)*1.6,y:(Math.random()-.5)*1.6,z:(Math.random()-.5)*1.6,
      vx:0,vy:0,vz:0,r:n.type==="agent"?(n.rank==="Admiral"?16:n.rank==="Commander"?14:n.rank==="Captain"?10:6.5):(n.type==="file"?4.5:8),
      core:(n.label==="Rosco"||n.label==="Ross"),links:0,pulse:0,tw:Math.random()*6.28};});
  E=m.edges.map(function(e){return[byId[e.a],byId[e.b],e.kind];}).filter(function(e){return e[0]!=null&&e[1]!=null;});
  E.forEach(function(e){N[e[0]].links++;N[e[1]].links++;});
  layout(); if(N.length){ selected=byId["Rosco"]!=null?byId["Rosco"]:0; resize(); }
});}

function layout(){ // simple 3D force: repel all pairs, spring edges, center pull
  for(var it=0;it<220;it++){var k=1-it/260;
    for(var i=0;i<N.length;i++){var a=N[i];
      for(var j=i+1;j<N.length;j++){var b=N[j];var dx=a.x-b.x,dy=a.y-b.y,dz=a.z-b.z;
        var d2=dx*dx+dy*dy+dz*dz+.01,f=.010/d2*k;a.vx+=dx*f;a.vy+=dy*f;a.vz+=dz*f;b.vx-=dx*f;b.vy-=dy*f;b.vz-=dz*f;}}
    E.forEach(function(e){var a=N[e[0]],b=N[e[1]];var dx=b.x-a.x,dy=b.y-a.y,dz=b.z-a.z;
      var d=Math.sqrt(dx*dx+dy*dy+dz*dz)||.01,f=(d-.55)*.06*k;a.vx+=dx/d*f;a.vy+=dy/d*f;a.vz+=dz/d*f;b.vx-=dx/d*f;b.vy-=dy/d*f;b.vz-=dz/d*f;});
    for(var m=0;m<N.length;m++){var n=N[m];n.vx-=n.x*.006;n.vy-=n.y*.006;n.vz-=n.z*.006;
      n.x+=n.vx;n.y+=n.vy;n.z+=n.vz;n.vx*=.82;n.vy*=.82;n.vz*=.82;}}
  // normalize to a nice radius
  var mx=0;N.forEach(function(n){mx=Math.max(mx,Math.hypot(n.x,n.y,n.z));});mx=mx||1;
  N.forEach(function(n){n.x/=mx;n.y/=mx;n.z/=mx;});
}

var yaw=-.5,pitch=-.26,tYaw=yaw,tPitch=pitch,drag=false,lx=0,ly=0,auto=!reduce,hover=-1,selected=-1;
function rot(p){var cy=Math.cos(yaw),sy=Math.sin(yaw),x=p.x*cy-p.z*sy,z=p.x*sy+p.z*cy,y=p.y,cx=Math.cos(pitch),sx=Math.sin(pitch);
  return{x:x,y:y*cx-z*sx,z:y*sx+z*cx};}
var cv=document.getElementById("cv"),ctx=cv.getContext("2d"),W=0,H=0,DPR=1;
function resize(){DPR=Math.min(window.devicePixelRatio||1,2);var b=cv.getBoundingClientRect();W=b.width;H=b.height;cv.width=W*DPR;cv.height=H*DPR;ctx.setTransform(DPR,0,0,DPR,0,0);}
window.addEventListener("resize",resize);
// The canvas is first measured while #app is display:none (0x0) and only re-sized
// on a window resize - so on unlock the graph rendered onto a 0x0 canvas and
// stayed invisible until something nudged the window. Observe the canvas itself:
// the moment it gains a real size (unlock, layout settle, DevTools), re-measure.
if(window.ResizeObserver){try{new ResizeObserver(function(){resize();}).observe(cv);}catch(e){}}
function project(r){var fov=3.4,scale=Math.min(W,H)*.42,f=fov/(fov+r.z);return{x:W/2+r.x*scale*f,y:H/2+r.y*scale*f,f:f,z:r.z};}
function fire(){if(!E.length)return;var e=E[(Math.random()*E.length)|0];signals.push({from:e[0],to:e[1],t:0,sp:.012+Math.random()*.014});}

function frame(){var T=performance.now();
  // Self-heal a stale 0x0 canvas (measured while hidden): if it now has a real
  // size, adopt it; if still zero, keep the loop alive but skip the dead draw.
  if(!W||!H){resize();if(!W||!H){return requestAnimationFrame(frame);}}
  if(auto&&!drag)tYaw+=.0015;yaw+=(tYaw-yaw)*.08;pitch+=(tPitch-pitch)*.08;ctx.clearRect(0,0,W,H);
  for(var i=0;i<N.length;i++){var r=rot(N[i]),p=project(r);N[i].px=p.x;N[i].py=p.y;N[i].pf=p.f;N[i].pz=r.z;
    N[i].pr=N[i].r*p.f*(1+Math.min(N[i].links,10)*.03);if(N[i].pulse>0)N[i].pulse*=.955;}
  var sel=null;if(selected>=0&&N[selected]){sel={};E.forEach(function(e){if(e[0]===selected)sel[e[1]]=1;if(e[1]===selected)sel[e[0]]=1;});sel[selected]=1;}
  ctx.globalCompositeOperation="lighter";
  for(var j=0;j<E.length;j++){var a=N[E[j][0]],b=N[E[j][1]];var k=(((a.pf+b.pf)/2)-.55)/.5;k=Math.max(0,Math.min(1,k));
    var near=sel&&sel[E[j][0]]&&sel[E[j][1]];ctx.beginPath();ctx.moveTo(a.px,a.py);ctx.lineTo(b.px,b.py);
    ctx.strokeStyle=near?"rgba(201,162,39,"+(.5*k+.15)+")":"rgba(55,176,160,"+(.13*k+.03)+")";ctx.lineWidth=near?1.4:.8;ctx.stroke();}
  for(var s=signals.length-1;s>=0;s--){var sg=signals[s];sg.t+=sg.sp;var a2=N[sg.from],b2=N[sg.to];if(!a2||!b2){signals.splice(s,1);continue;}
    for(var tt=0;tt<4;tt++){var tp=Math.max(0,sg.t-tt*.05),x=a2.px+(b2.px-a2.px)*tp,y=a2.py+(b2.py-a2.py)*tp;
      ctx.globalAlpha=(1-tt/4)*.9;ctx.beginPath();ctx.arc(x,y,(2.4-tt*.5)*((a2.pf+b2.pf)/2),0,7);ctx.fillStyle="#ffe9a8";ctx.fill();}
    ctx.globalAlpha=1;if(sg.t>=1){N[sg.to].pulse=1;signals.splice(s,1);}}
  var order=N.map(function(n,ix){return ix;}).sort(function(x,y){return N[x].pz-N[y].pz;});
  for(var o=0;o<order.length;o++){var ix=order[o],n=N[ix];var k2=(n.pf-.55)/.5;k2=Math.max(.25,Math.min(1,k2));
    var col=n.core?TYPEC.core:TYPEC[n.type]||"#8aa";var base=n.pr,glow=n.pulse,hi=(ix===hover||ix===selected),dim=sel&&!sel[ix];
    var tw=.82+.18*Math.sin(T/650+n.tw),spr=sprite[n.core?"core":n.type]||sprite.agent,gs=base*(3.4+glow*5)*(hi?1.3:1);
    ctx.globalAlpha=(dim?.1:.55*k2)*tw;ctx.drawImage(spr,n.px-gs,n.py-gs,gs*2,gs*2);
    ctx.globalCompositeOperation="source-over";ctx.globalAlpha=dim?.3:1;
    var rad=Math.max(1.2,base*(1+glow*0.9)*(hi?1.25:1));    // the node SWELLS while active
    if(glow>.04&&!dim){ctx.globalAlpha=glow*.5;ctx.beginPath();ctx.arc(n.px,n.py,rad+(1-glow)*15+2,0,7);ctx.strokeStyle=col;ctx.lineWidth=1.6;ctx.stroke();ctx.globalAlpha=dim?.3:1;}
    ctx.beginPath();ctx.arc(n.px,n.py,rad,0,7);ctx.fillStyle=dim?"#3a4640":col;ctx.fill();
    if(n.core){ctx.beginPath();ctx.arc(n.px,n.py,base+4,0,7);ctx.strokeStyle=col;ctx.globalAlpha=dim?.2:.7;ctx.lineWidth=1;ctx.stroke();}
    if(n.waiting&&!dim){var pw=base+7+2*Math.sin(T/300+n.tw);ctx.beginPath();ctx.arc(n.px,n.py,pw,0,7);
      ctx.strokeStyle="#c9a227";ctx.globalAlpha=.5+.3*Math.sin(T/300+n.tw);ctx.lineWidth=1.4;ctx.stroke();}
    ctx.globalAlpha=1;
    if((n.r>=10||hi)&&!dim){ctx.font="700 "+(n.r>=14?12:10.5)+"px ui-monospace,Consolas,monospace";ctx.fillStyle="#e8efeb";ctx.textAlign="center";ctx.fillText(n.label,n.px,n.py-base-7);}
    ctx.globalCompositeOperation="lighter";}
  ctx.globalCompositeOperation="source-over";requestAnimationFrame(frame);
}
function pick(mx,my){var best=-1;for(var i=0;i<N.length;i++){var d=Math.hypot(N[i].px-mx,N[i].py-my),hit=Math.max(9,N[i].pr+7);
  if(d<hit&&(best<0||N[i].pz>N[best].pz))best=i;}return best;}
var tip=document.getElementById("tip");
cv.addEventListener("mousemove",function(e){var b=cv.getBoundingClientRect(),mx=e.clientX-b.left,my=e.clientY-b.top;
  if(drag){tYaw+=(mx-lx)*.008;tPitch+=(my-ly)*.006;tPitch=Math.max(-1.2,Math.min(1.2,tPitch));lx=mx;ly=my;return;}
  hover=pick(mx,my);if(hover>=0){var n=N[hover];tip.innerHTML=esc(n.label)+"<br><span class='r'>"+esc(((n.rank||n.type)+"").toUpperCase())+(n.biz?" · "+esc((n.biz+"").toUpperCase()):"")+"</span>";
    tip.style.left=n.px+"px";tip.style.top=n.py+"px";tip.style.opacity=1;cv.style.cursor="pointer";}
  else{tip.style.opacity=0;cv.style.cursor=drag?"grabbing":"grab";}});
cv.addEventListener("mousedown",function(e){drag=true;auto=false;var b=cv.getBoundingClientRect();lx=e.clientX-b.left;ly=e.clientY-b.top;});
window.addEventListener("mouseup",function(){drag=false;});
cv.addEventListener("click",function(e){var b=cv.getBoundingClientRect(),p=pick(e.clientX-b.left,e.clientY-b.top);
  if(p>=0){selected=p;N[p].pulse=1;showNode(N[p]);}});
cv.addEventListener("mouseleave",function(){tip.style.opacity=0;hover=-1;});

// ---- context panel: click a node -> its details; "back" -> the queue ----
function showNode(n){
  var ctx=document.getElementById("ctx");
  var col=(n.core?"#e8efeb":(TYPEC[n.type]||"#8aa"));
  var neigh=[]; E.forEach(function(e){ if(e[0]===byId[n.id])neigh.push(N[e[1]]); if(e[1]===byId[n.id])neigh.push(N[e[0]]); });
  var links=neigh.slice(0,12).map(function(m){ return "<span class='lchip' data-jump='"+esc(m.id)+"'>"+esc(m.label)+"</span>"; }).join(" ");
  ctx.innerHTML="<div class='back' id='back'>&larr; back to the queue</div>"
    +"<div class='node-ctx'>"
    +"<div class='nm'>"+esc(n.label)+"</div>"
    +"<div class='rk' style='color:"+col+"'>"+esc(n.rank||n.type)+"</div>"
    +(n.type==="file"?("<div class='kv'><div class='k'>Source</div><div class='v'>"+esc(n.source||"")+"</div></div>"
       +"<div class='kv'><div class='k'>Status</div><div class='v'>"+(n.learned?"learned into "+esc(n.business||""):"queued — not learned yet")+"</div></div>"
       +"<div class='kv'><div class='k'>Detail</div><div class='v'>full copy cached locally — read without the internet</div></div>"):"")
    +(n.biz?"<div class='kv'><div class='k'>Business</div><div class='v'>"+esc(n.biz)+"</div></div>":"")
    +(n.reports?"<div class='kv'><div class='k'>Reports to</div><div class='v'>"+esc(n.reports)+"</div></div>":"")
    +(links?"<div class='kv'><div class='k'>Linked</div><div class='v' style='display:flex;flex-wrap:wrap;gap:5px'>"+links+"</div></div>":"")
    +"</div>";
  document.getElementById("back").addEventListener("click",restoreQueue);
  ctx.querySelectorAll("[data-jump]").forEach(function(el){el.addEventListener("click",function(){
    var i=byId[el.getAttribute("data-jump")]; if(i!=null){selected=i;N[i].pulse=1;showNode(N[i]);}});});
  // Agents (graph nodes) can be pinned to their own model, right here. People,
  // sites and tools have no model, so the picker is agents-only.
  if(n.type==="agent") buildAgentModel(n, ctx.querySelector(".node-ctx"));
}

// The per-agent model picker inside a node's panel. Pinning an agent overrides
// its role default; unpinning falls back. Provider -> live model list (same
// endpoint the Models settings uses) -> Pin. Every write is /api/cfg/pin|unpin,
// which only Ross's unlocked session can call.
function buildAgentModel(n, host){
  if(!host) return;
  var box=document.createElement("div"); box.className="amodel";
  box.innerHTML="<div class='amh'>Model</div><div class='amcur n'>loading…</div>";
  host.appendChild(box);
  var curLine=box.querySelector(".amcur");
  var provSel=document.createElement("select"); provSel.className="amsel";
  var mwrap=document.createElement("div"); mwrap.className="amwrap";
  var row=document.createElement("div"); row.className="amrow";
  var pinBtn=document.createElement("button"); pinBtn.className="go sm"; pinBtn.textContent="Pin model";
  var res=document.createElement("div"); res.className="res";
  var modelEl=null;
  function fillModels(preselect){
    mwrap.innerHTML="<div class='n'>loading models…</div>";
    api("/api/cfg/models?provider="+encodeURIComponent(provSel.value)).then(function(r){
      mwrap.innerHTML="";
      var ids=(r.ok&&r.j&&r.j.models)||[];
      if(ids.length){var sel=document.createElement("select"); sel.className="amsel";
        if(preselect&&ids.indexOf(preselect)<0){var oc=document.createElement("option");oc.value=preselect;oc.textContent=preselect+" (current)";sel.appendChild(oc);}
        ids.forEach(function(id){var o=document.createElement("option");o.value=id;o.textContent=id;sel.appendChild(o);});
        if(preselect)sel.value=preselect;
        mwrap.appendChild(sel); modelEl=sel;
      } else {var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";inp.autocomplete="off";
        if(preselect)inp.value=preselect;
        mwrap.appendChild(inp); modelEl=inp;
        if(r.j&&r.j.error){var e=document.createElement("div");e.className="n";e.textContent=esc(r.j.error);mwrap.appendChild(e);}
      }
    }).catch(function(){mwrap.innerHTML="";var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";mwrap.appendChild(inp);modelEl=inp;});
  }
  api("/api/cfg/state").then(function(r){
    var st=(r.ok&&r.j)||{};
    var provs=st.providers||["openrouter","anthropic","openai","gemini","xai","ollama"];
    provs.forEach(function(p){var o=document.createElement("option");o.value=p;o.textContent=p;provSel.appendChild(o);});
    var pin=(st.pins&&st.pins[n.id])||null;
    if(pin){curLine.className="amcur";
      curLine.innerHTML="Pinned to <b>"+esc(pin.model)+"</b> via "+esc(pin.provider)+" &middot; <span class='unpin'>unpin</span>";
      curLine.querySelector(".unpin").addEventListener("click",function(){
        post("/api/cfg/unpin",{agent:n.id}).then(function(r){ if(r.ok)showNode(n);
          else{res.className="res err";res.textContent=(r.j&&r.j.error)||"failed";}});});
    } else {curLine.className="amcur n"; curLine.textContent="Using its role default — not pinned.";}
    provSel.value=pin?pin.provider:"openrouter";
    fillModels(pin?pin.model:"");
  });
  provSel.addEventListener("change",function(){fillModels("");});
  pinBtn.addEventListener("click",function(){
    if(!modelEl||!modelEl.value){res.className="res err";res.textContent="pick a model first";return;}
    pinBtn.disabled=true; res.className="res"; res.textContent="working…";
    post("/api/cfg/pin",{agent:n.id,model:modelEl.value,provider:provSel.value}).then(function(r){
      pinBtn.disabled=false;
      if(r.ok)showNode(n);   // re-render; the updated "Pinned to…" line is the confirmation
      else{res.className="res err";res.textContent=(r.j&&r.j.error)||"failed";}
    }).catch(function(){pinBtn.disabled=false;res.className="res err";res.textContent="server unreachable";});
  });
  row.appendChild(provSel); row.appendChild(mwrap);
  box.appendChild(row); box.appendChild(pinBtn); box.appendChild(res);
}
function restoreQueue(){
  document.getElementById("ctx").innerHTML=
    "<div class='rhead' id='rhead'>Waiting on you</div><div class='qwrap' id='qwrap'></div>";
  loadQueue();
}

// ---- tools rail: each one shows its view in the right-panel context area ----
var TOOLS=[["Mesh","M12 3v4M12 17v4M3 12h4M17 12h4M12 8a4 4 0 100 8 4 4 0 000-8z"],
  ["Queue","M4 6h16M4 12h16M4 18h10"],["People","M9 11a3 3 0 100-6 3 3 0 000 6zm7 8a7 7 0 00-14 0"],
  ["Tools","M14 7l3 3-8 8-3-3zM3 21l4-1"],["Spend","M4 18l5-6 4 4 7-9"],["Verify","M20 6L9 17l-5-5"]];
function showTool(name){
  // Mesh = the graph (always centre) with the default queue on the right; Queue = the same list.
  if(name==="Mesh"||name==="Queue"){selected=byId["Rosco"]!=null?byId["Rosco"]:selected;restoreQueue();return;}
  var ctx=document.getElementById("ctx");
  // note: no #rhead/#qwrap ids here, so the 15s queue poll won't clobber this view
  ctx.innerHTML="<div class='rhead'>"+esc(name)+"</div><div class='stream' id='toolbody'><div class='empty'>Loading…</div></div>";
  var body=document.getElementById("toolbody");
  function card(title,sub){return "<div class='ask'><div class='top'><span class='who'>"+esc(title)+"</span></div>"+(sub?"<div class='said'>"+sub+"</div>":"")+"</div>";}
  if(name==="People"){
    Promise.all([api("/api/people"),api("/api/grants")]).then(function(res){
      var ppl=(res[0].ok&&Array.isArray(res[0].j))?res[0].j:[], gr=(res[1].ok&&Array.isArray(res[1].j))?res[1].j:[];
      if(!ppl.length){body.innerHTML="<div class='empty'>No one enrolled yet.</div>";return;}
      body.innerHTML=ppl.map(function(p){
        var acc=gr.filter(function(g){return g.person===p.person&&g.allow;}).map(function(g){return g.business+":"+g.capability;});
        var ch=(p.handles||[]).map(function(h){return h.channel;}).join(", ");
        return card(p.person, esc(ch||"no channels")+(acc.length?"<br><span style='color:var(--dim)'>can reach: "+esc(acc.join(", "))+"</span>":""));
      }).join("");
    }).catch(function(){body.innerHTML="<div class='empty'>couldn't load people</div>";});
  } else if(name==="Spend"){
    api("/api/spend").then(function(r){var d=(r.ok&&r.j)||{};
      body.innerHTML="<pre class='mono' style='white-space:pre-wrap;font-size:11.5px;color:var(--text);padding:2px 4px;margin:0'>"+esc(d.report||"(no spend yet)")+"</pre>"
        +"<div class='said' style='padding:0 4px;color:var(--dim)'>caps: "+esc((d.budgets||[]).map(function(b){return b.scope+" $"+b.cap;}).join(", ")||"none set")+"</div>";
    }).catch(function(){body.innerHTML="<div class='empty'>couldn't load spend</div>";});
  } else if(name==="Verify"){
    api("/api/overview").then(function(r){var o=(r.ok&&r.j)||{};
      var col=o.chains==="sound"?"var(--green)":"var(--amber)";
      body.innerHTML=card("Chain integrity","<b style='color:"+col+"'>"+esc(o.chains||"?")+"</b> — every event's hash links to the prior")
        +card("Spend","$"+esc(o.spend!=null?o.spend.toFixed(2):"?")+" over "+esc(o.spendCalls||0)+" model calls")
        +card("Waiting on you",esc(o.waiting||0)+" request(s)");
    }).catch(function(){body.innerHTML="<div class='empty'>couldn't verify</div>";});
  } else if(name==="Tools"){
    api("/api/cfg/state").then(function(r){var d=(r.ok&&r.j)||{};
      var tools=d.tools||[], repos=d.repos||[];
      var html=tools.length?tools.map(function(t){return card(t.name,esc((t.businesses||[]).join(", ")||"*"));}).join(""):"<div class='empty'>No external tools registered.</div>";
      if(repos.length)html+="<div class='rhead' style='border-top:1px solid var(--line)'>Linked repos</div>"+repos.map(function(rp){return card(rp.slug||rp.repo||rp.business||JSON.stringify(rp),"");}).join("");
      body.innerHTML=html;
    }).catch(function(){body.innerHTML="<div class='empty'>couldn't load tools</div>";});
  }
}
var tel=document.getElementById("tools");
TOOLS.forEach(function(t,i){var el=document.createElement("div");el.className="tool"+(i===0?" on":"");
  el.innerHTML="<svg viewBox='0 0 24 24'><path d='"+t[1]+"'/></svg><span class='t'>"+t[0]+"</span>";
  el.addEventListener("click",function(){tel.querySelectorAll(".tool").forEach(function(x){x.classList.remove("on");});el.classList.add("on");showTool(t[0]);});
  tel.appendChild(el);});

// ---- chat with Rosco ----
function bubble(cls,by,text){var m=document.createElement("div");m.className="msg "+cls;
  var b=document.createElement("div");b.className="by";b.textContent=by;
  var d=document.createElement("div");d.className="bub";d.textContent=text;
  // render a generated image inline: a 🖼️ reply carries its URL (any CDN); else
  // any image-extension URL in the text.
  var url=null;
  if((text||"").indexOf("🖼")>=0){var u=(text||"").match(/https?:\/\/\S+/);if(u)url=u[0];}
  if(!url){var g=(text||"").match(/https?:\/\/\S+\.(?:png|jpe?g|webp|gif)(?:\?\S*)?/i);if(g)url=g[0];}
  if(url){var img=document.createElement("img");img.className="genimg";img.src=url;img.alt="generated image";
    img.addEventListener("error",function(){img.remove();});d.appendChild(img);}
  m.appendChild(b);m.appendChild(d);var s=document.getElementById("stream");
  s.appendChild(m);s.scrollTop=s.scrollHeight;return m;}
// A snapshot of what Ross is looking at, so "the queue" / "this node" / "this
// button" resolve to what's on screen. Sent with every chat message.
function dashState(){
  var tool="";var on=document.querySelector(".tool.on .t");if(on)tool=on.textContent;
  var node=(typeof selected!=="undefined"&&selected>=0&&N[selected])?N[selected].label:"";
  var ctx=document.getElementById("ctx");
  var visible=ctx?((ctx.innerText||ctx.textContent||"").replace(/\s+/g," ").trim().slice(0,700)):"";
  return {tool:tool,node:node,visible:visible};
}
function sendChat(){
  var inp=document.getElementById("chatin"),btn=document.getElementById("chatsend");
  var msg=inp.value.trim(); if(!msg) return;
  bubble("you","Ross",msg); inp.value=""; btn.disabled=true;
  var waiting=bubble("wait","Rosco","thinking…");
  post("/api/chat",{message:msg,ui:dashState()}).then(function(res){
    waiting.remove(); btn.disabled=false; inp.focus();
    if(res.ok){ bubble("ros","Rosco", res.j.reply||"…"); }
    else{ bubble("ros","Rosco", (res.j&&res.j.error)||"couldn't reach the model."); }
  }).catch(function(){ waiting.remove(); btn.disabled=false;
    bubble("ros","Rosco","server unreachable."); });
}
document.getElementById("chatsend").addEventListener("click",sendChat);
// Starts readonly so Chrome's password manager won't pair it with the unlock
// passphrase field and offer to autofill a password into the chat box; drop that
// the moment it's focused so typing works normally.
document.getElementById("chatin").addEventListener("focus",function(){this.removeAttribute("readonly");});
document.getElementById("chatin").addEventListener("keydown",function(e){if(e.key==="Enter")sendChat();});

// ---- settings: the CLI's config commands, as forms ----
var CFG=[
 {t:"Models",a:"model",n:"Pick a role, a provider, then a model your key can serve.",
  f:[{k:"role",l:"Role",sel:"roles"},{k:"provider",l:"Provider",sel:"providers"},{k:"model",l:"Model",dyn:"models"}]},
 {t:"API keys",a:"secret",n:"Stored encrypted in the vault. A live green check means the provider accepts it. Model keys use scope 'system'; a connector credential (Google, GitHub) goes under its business. Click a row to fill its name.",
  f:[{k:"business",l:"Scope",sel:"scopes"},{k:"name",l:"Key name",ph:"openrouter_api_key"},{k:"value",l:"Value",type:"password"}]},
 {t:"Google Workspace",google:true,n:"Connect each Google account by OAuth — full Gmail/Drive/Calendar/Docs/Sheets/Chat/Contacts. First store that account's google_client_id + google_client_secret above (scope = the business), then Authorize and consent as the right account in the tab that opens.",f:[]},
 {t:"GitHub",gh:true,n:"Paste a fine-grained token (Contents: Read on the repos you want Rosco to see; add Pull requests: Read+write for PRs). It's stored as github_token and Rosco can then browse and read your repos in chat.",f:[]},
 {t:"Test a model",a:"test",btn:"Test",n:"Pings the model a role actually uses and reports the raw reply — or the exact provider error. Use it right after pasting a key.",
  f:[{k:"role",l:"Role",sel:"roles"}]},
 {t:"Spend cap",a:"budget",n:"A soft monthly cap. Warns at 80% and 100%; never blocks.",
  f:[{k:"scope",l:"Scope (* = all)",ph:"*"},{k:"usd",l:"Monthly $",ph:"200"}]},
 {t:"Teach a business",a:"ingest",n:"Paste a doc to load as lessons, or leave blank to load the starter facts.",
  f:[{k:"business",l:"Business",sel:"businesses"},{k:"text",l:"Doc (optional)",type:"textarea"}]},
 {t:"Enrol a person",a:"enrol",n:"Telegram/chat prove identity; email/phone are treated as spoofable.",
  f:[{k:"person",l:"Name",ph:"brent"},{k:"channel",l:"Channel",opt:["telegram","chat","email","phone"]},{k:"address",l:"Address or id",ph:"8481123"}]},
 {t:"Telegram bot",a:"secret",fixed:{name:"telegram_bot_token"},tg:true,
  n:"Give Rosco a phone line. Create a bot with @BotFather, paste its token here — a green ● with the @name means Telegram accepts it. Then, in a terminal: `rosco serve` starts the bot, and `rosco pair` links your own phone.",
  f:[{k:"value",l:"BotFather token",type:"password",ph:"123456:ABC-DEF…"}]},
 {t:"Grant a capability",a:"grant",n:"Who may reach what. 'subject' scope = only rows about them.",
  f:[{k:"person",l:"Person"},{k:"business",l:"Business",sel:"businesses"},{k:"capability",l:"Capability",sel:"capabilities"},{k:"verb",l:"Verb",opt:["get","do"]},{k:"scope",l:"Scope",opt:["all","subject"]}]},
 {t:"External tool",a:"tool",n:"An endpoint agents can be granted. The key goes in the vault.",
  f:[{k:"name",l:"Name",ph:"higgsfield"},{k:"endpoint",l:"HTTPS endpoint",ph:"https://…"},{k:"businesses",l:"Businesses (comma, * = any)",ph:"*"},{k:"secret",l:"Key name (optional)",ph:"higgsfield_api_key"},{k:"caution",l:"Caution (optional)"}]},
 {t:"Link a repo",a:"github",n:"Agents branch and open PRs; you merge on GitHub.",
  f:[{k:"business",l:"Business",sel:"businesses"},{k:"repo",l:"owner/name",ph:"fuzzeh84/rumachines"},{k:"branch",l:"Default branch",ph:"main"},{k:"secret",l:"Token name",ph:"github_token"}]},
];
var cfgState={};
function openSettings(){ document.getElementById("settings").style.display="flex";
  api("/api/cfg/state").then(function(res){ cfgState=(res.ok&&res.j)?res.j:{}; renderState(); buildForms(); }); }
function closeSettings(){ document.getElementById("settings").style.display="none"; }
function renderState(){var s=cfgState,el=document.getElementById("cfgState");
  if(!s.roles){el.textContent="(couldn't load settings)";return;}
  var mods=s.roles.map(function(r){var m=(s.models&&s.models[r])||{};
    return r+" → "+(m.model||"?")+" ("+(m.provider||"?")+")";}).join("\n");
  var keys=(s.secretsHeld||[]).length?(s.secretsHeld||[]).join(", "):"none";
  var miss=(s.missingKeys||[]);
  el.innerHTML="<b>Models</b>\n"+esc(mods)
    +"\n\n<b>Keys held</b> "+esc(keys)
    +(miss.length?"  <span class='warn'>missing: "+esc(miss.join(", "))+"</span>":"")
    +"\n<b>Budgets</b> "+esc((s.budgets||[]).map(function(b){return b.scope+" $"+b.cap;}).join(", ")||"none")
    +"\n<b>Tools</b> "+esc((s.tools||[]).map(function(t){return t.name;}).join(", ")||"none")
    +"  <b>Repos</b> "+esc((s.repos||[]).map(function(r){return r.slug;}).join(", ")||"none")
    +"  <b>People</b> "+esc((s.people||[]).join(", ")||"none");
}
function optionsFor(field){
  if(field.opt) return field.opt;
  if(field.sel==="scopes") return ["system"].concat((cfgState.businesses||[]).filter(function(b){return b!=="system";})); // model keys -> system; connector creds -> a business (system listed once)
  if(field.sel && Array.isArray(cfgState[field.sel])) return cfgState[field.sel];
  return null;
}
// The persisted key panel under Models: one row per provider, a live dot -
// green (provider accepts the stored key), red (rejected), amber (stored but
// unverified/unreachable), grey (nothing stored). Clicking a row fills the key
// name so a paste goes to the right slot. Probing is live, so show it working.
function loadKeyStatus(el,nameInput,scopeInput){
  el.innerHTML="<div class='n'>checking stored keys…</div>";
  api("/api/cfg/keystatus").then(function(r){
    el.innerHTML="";
    var keys=(r.ok&&r.j&&Array.isArray(r.j.keys))?r.j.keys:[];
    if(!keys.length){el.innerHTML="<div class='n'>(no key status)</div>";return;}
    keys.forEach(function(k){
      var cls=(k.valid===true)?"g":(k.valid===false)?"r":(k.stored?"a":"o");
      var st=(k.valid===true)?"valid":(k.valid===false)?(k.detail||"rejected")
             :(k.stored?(k.detail||"unverified"):"not set");
      var row=document.createElement("div");row.className="ksrow";
      var dot=document.createElement("span");dot.className="dot "+cls;
      var nm=document.createElement("span");nm.className="ksname";nm.textContent=k.provider;
      var sv=document.createElement("span");sv.className="ksst "+cls;sv.textContent=st;
      row.appendChild(dot);row.appendChild(nm);row.appendChild(sv);
      if(k.provider!=="ollama"&&k.secret){row.classList.add("pick");
        row.addEventListener("click",function(){
          if(scopeInput)scopeInput.value="system";             // model keys always live in system scope
          if(nameInput){nameInput.value=k.secret;nameInput.focus();}});}
      loadProviderModels(row,k.provider);                      // fill in this provider's live catalogue
      el.appendChild(row);
    });
  }).catch(function(){el.innerHTML="<div class='n'>(couldn't check keys)</div>";});
}
// Each provider row shows its live model catalogue as a dropdown right under the
// status, AND lets you assign a model to a role from there. Only where there ARE
// models: openrouter and ollama list without a key; anthropic/openai/gemini/xai
// need a valid key, so a keyless provider shows none and its "not set" status
// stands as the answer. Pick a model -> a "use for <role>" strip appears ->
// Assign writes it via /api/cfg/model (the same choose() the Models form uses).
function loadProviderModels(row,provider){
  api("/api/cfg/models?provider="+encodeURIComponent(provider)).then(function(r){
    var ids=(r.ok&&r.j&&r.j.models)||[];
    if(!ids.length) return;
    var sel=document.createElement("select");sel.className="ksmsel";
    var head=document.createElement("option");head.value="";
    head.textContent=ids.length+" model"+(ids.length===1?"":"s")+" available — pick one to assign";
    sel.appendChild(head);
    ids.forEach(function(id){var o=document.createElement("option");o.value=id;o.textContent=id;sel.appendChild(o);});
    sel.addEventListener("click",function(e){e.stopPropagation();});   // don't trip the row's fill-key-name click
    // the assign strip: hidden until a real model is chosen
    var strip=document.createElement("div");strip.className="ksassign";strip.style.display="none";
    strip.addEventListener("click",function(e){e.stopPropagation();});
    var roleSel=document.createElement("select");roleSel.className="karole";
    (cfgState.roles||["chat","workhorse","cheap","vision","local"]).forEach(function(rl){
      var o=document.createElement("option");o.value=rl;o.textContent="use for "+rl;roleSel.appendChild(o);});
    var apply=document.createElement("button");apply.className="go sm";apply.textContent="Assign";
    var res=document.createElement("span");res.className="ksares";
    sel.addEventListener("change",function(){strip.style.display=sel.value?"flex":"none";res.textContent="";res.className="ksares";});
    apply.addEventListener("click",function(){
      var model=sel.value; if(!model){res.className="ksares err";res.textContent="pick a model";return;}
      apply.disabled=true;res.className="ksares";res.textContent="working…";
      post("/api/cfg/model",{role:roleSel.value,model:model,provider:provider}).then(function(rr){
        apply.disabled=false;
        if(rr.ok){res.className="ksares ok";res.textContent=rr.j.msg||"set";
          api("/api/cfg/state").then(function(x){if(x.ok&&x.j){cfgState=x.j;renderState();}});}
        else{res.className="ksares err";res.textContent=(rr.j&&rr.j.error)||"failed";}
      }).catch(function(){apply.disabled=false;res.className="ksares err";res.textContent="unreachable";});
    });
    strip.appendChild(roleSel);strip.appendChild(apply);strip.appendChild(res);
    row.appendChild(sel);row.appendChild(strip);
  }).catch(function(){});
}
// The bot-token line: green ● @name when Telegram's getMe accepts it, red when
// it's rejected, grey when nothing's stored. Same look as the key rows.
function loadTelegramStatus(el){
  el.innerHTML="<div class='n'>checking bot token…</div>";
  api("/api/cfg/telegram").then(function(r){
    el.innerHTML="";
    var k=(r.ok&&r.j)?r.j:{};
    var cls=(k.valid===true)?"g":(k.valid===false)?"r":(k.stored?"a":"o");
    var st=(k.valid===true)?("live "+(k.username||"")):(k.valid===false)?"token rejected"
           :(k.stored?(k.detail||"unverified"):"not set");
    var row=document.createElement("div");row.className="ksrow";
    var dot=document.createElement("span");dot.className="dot "+cls;
    var nm=document.createElement("span");nm.className="ksname";nm.textContent="bot";
    var sv=document.createElement("span");sv.className="ksst "+cls;sv.textContent=st;
    row.appendChild(dot);row.appendChild(nm);row.appendChild(sv);el.appendChild(row);
  }).catch(function(){el.innerHTML="<div class='n'>(couldn't check bot)</div>";});
}
// ---- settings sidebar: one section at a time, no long scroll ----
var cfgSel=-1;
function addNav(sec,label){var nav=document.getElementById("cfgNav");if(!nav)return;
  var b=document.createElement("div");b.className="ni";b.setAttribute("data-sec",String(sec));b.textContent=label;
  b.addEventListener("click",function(){selectSection(sec);});nav.appendChild(b);}
function selectSection(sec){cfgSel=sec;var S=String(sec);
  var state=document.getElementById("cfgState");if(state)state.style.display=(S==="-1")?"block":"none";
  var forms=document.getElementById("cfgForms");if(forms){var cs=forms.children;
    for(var i=0;i<cs.length;i++){cs[i].style.display=(cs[i].getAttribute("data-sec")===S)?"block":"none";}}
  var nav=document.getElementById("cfgNav");if(nav){var ns=nav.children;
    for(var j=0;j<ns.length;j++){ns[j].classList.toggle("on",ns[j].getAttribute("data-sec")===S);}}
}
function buildForms(){var host=document.getElementById("cfgForms");host.innerHTML="";
  var nav=document.getElementById("cfgNav");if(nav)nav.innerHTML="";addNav(-1,"Overview");
  CFG.forEach(function(sec,idx){
    var card=document.createElement("div");card.className="cfg";card.setAttribute("data-sec",idx);
    var h=document.createElement("h4");h.textContent=sec.t;card.appendChild(h);
    if(sec.n){var nn=document.createElement("div");nn.className="n";nn.textContent=sec.n;card.appendChild(nn);}
    if(sec.google){renderGooglePane(card);host.appendChild(card);addNav(idx,sec.t);return;}
    if(sec.gh){renderGithubPane(card);host.appendChild(card);addNav(idx,sec.t);return;}
    var inputs={},dyn={},ksEl=null,tgEl=null;
    if(sec.a==="secret"&&!sec.tg){ksEl=document.createElement("div");ksEl.className="keystat";card.appendChild(ksEl);}
    if(sec.tg){tgEl=document.createElement("div");tgEl.className="keystat";card.appendChild(tgEl);}
    sec.f.forEach(function(fl){
      var lab=document.createElement("label");lab.textContent=fl.l;card.appendChild(lab);
      if(fl.dyn){var wrap=document.createElement("div");card.appendChild(wrap);dyn[fl.k]=wrap;inputs[fl.k]=null;return;}
      var opts=optionsFor(fl),el;
      if(opts){el=document.createElement("select");opts.forEach(function(o){var op=document.createElement("option");op.value=o;op.textContent=o;el.appendChild(op);});}
      else if(fl.type==="textarea"){el=document.createElement("textarea");}
      else{el=document.createElement("input");el.type=fl.type||"text";if(fl.ph)el.placeholder=fl.ph;el.autocomplete="off";}
      card.appendChild(el);inputs[fl.k]=el;
    });
    // Models: the model list comes live from the chosen provider. Refetch on
    // provider change; if the provider has no listing, fall back to a text box.
    if(dyn.model && inputs.provider){
      var wrap=dyn.model;
      function curModel(){var role=inputs.role?inputs.role.value:"";return (cfgState.models&&cfgState.models[role])||{};}
      var fillModels=function(){
        var cur=curModel();
        wrap.innerHTML="<div class='n'>loading models…</div>";
        api("/api/cfg/models?provider="+encodeURIComponent(inputs.provider.value)).then(function(r){
          wrap.innerHTML="";
          var ids=(r.ok&&r.j&&r.j.models)||[];
          var onCur=cur.model&&inputs.provider.value===cur.provider;   // showing the role's current provider?
          if(ids.length){var sel=document.createElement("select");
            if(onCur&&ids.indexOf(cur.model)<0){var oc=document.createElement("option");oc.value=cur.model;oc.textContent=cur.model+" (current)";sel.appendChild(oc);}
            ids.forEach(function(id){var o=document.createElement("option");o.value=id;o.textContent=id;sel.appendChild(o);});
            if(onCur)sel.value=cur.model;                              // pre-select what's actually set
            wrap.appendChild(sel);inputs.model=sel;
          } else {var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";inp.autocomplete="off";
            if(onCur)inp.value=cur.model;
            wrap.appendChild(inp);inputs.model=inp;
            if(r.j&&r.j.error){var e=document.createElement("div");e.className="n";e.textContent=esc(r.j.error);wrap.appendChild(e);}
          }
        }).catch(function(){wrap.innerHTML="";var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";wrap.appendChild(inp);inputs.model=inp;});
      };
      // point provider + model at what THIS role currently uses
      var syncRole=function(){var cur=curModel();if(cur.provider&&inputs.provider)inputs.provider.value=cur.provider;fillModels();};
      inputs.provider.addEventListener("change",fillModels);
      if(inputs.role)inputs.role.addEventListener("change",syncRole);
      syncRole();
    }
    if(ksEl)loadKeyStatus(ksEl,inputs.name,inputs.business);
    if(tgEl)loadTelegramStatus(tgEl);
    var btn=document.createElement("button");btn.className="go";btn.textContent=sec.btn||"Apply";
    var res=document.createElement("div");res.className="res";
    btn.addEventListener("click",function(){
      var body={};for(var k in inputs){body[k]=inputs[k]?inputs[k].value:"";}
      if(sec.fixed)for(var fk in sec.fixed)body[fk]=sec.fixed[fk];   // e.g. the telegram card fixes name
      if(body.businesses!==undefined) body.businesses=body.businesses.split(",").map(function(x){return x.trim();}).filter(Boolean);
      btn.disabled=true;res.className="res";res.textContent="working…";
      post("/api/cfg/"+sec.a,body).then(function(r){btn.disabled=false;
        if(r.ok){res.className="res ok";res.textContent=r.j.msg||"done";
          if(inputs.value)inputs.value.value="";               // never keep a secret in the field
          api("/api/cfg/state").then(function(x){cfgState=(x.ok&&x.j)?x.j:cfgState;renderState();});
          if(ksEl)loadKeyStatus(ksEl,inputs.name,inputs.business);             // a saved key re-probes its status
          if(tgEl)loadTelegramStatus(tgEl);                    // a saved bot token re-probes via getMe
        } else {res.className="res err";res.textContent=(r.j&&r.j.error)||"failed";}
      }).catch(function(){btn.disabled=false;res.className="res err";res.textContent="server unreachable";});
    });
    card.appendChild(btn);card.appendChild(res);host.appendChild(card);
    addNav(idx,sec.t);
  });
  selectSection(cfgSel);
}
// ---- Google Workspace: per-account OAuth "Authorize" ----
function renderGooglePane(card){
  var wrap=document.createElement("div");wrap.className="keystat";card.appendChild(wrap);
  loadGoogleStatus(wrap);
}
function loadGoogleStatus(wrap){
  wrap.innerHTML="<div class='n'>checking Google connections…</div>";
  api("/api/google/status").then(function(r){
    wrap.innerHTML="";
    var accs=(r.ok&&r.j&&Array.isArray(r.j.accounts))?r.j.accounts:[];
    if(!accs.length){wrap.innerHTML="<div class='n'>(no accounts)</div>";return;}
    accs.forEach(function(a){
      var block=document.createElement("div");block.className="gacct";
      var cls=a.connected?"g":(a.clientReady?"o":"a");
      var st=a.connected?("connected "+(a.email||"")):(a.clientReady?"ready — not connected":"needs client id + secret");
      var row=document.createElement("div");row.className="ksrow";
      var dot=document.createElement("span");dot.className="dot "+cls;
      var nm=document.createElement("span");nm.className="ksname";nm.textContent=a.account;
      var sv=document.createElement("span");sv.className="ksst "+cls;sv.textContent=st;
      row.appendChild(dot);row.appendChild(nm);row.appendChild(sv);
      if(a.clientReady){                                   // only meaningful once the app creds exist
        var btn=document.createElement("button");btn.className="btn";btn.style.marginLeft="8px";
        btn.textContent=a.connected?"Reconnect":"Authorize";
        btn.addEventListener("click",function(){authorizeGoogle(a.account,btn,wrap);});
        row.appendChild(btn);
      }
      block.appendChild(row);
      // Inline app credentials, right here — no hunting through API keys. Stored
      // under this account's own vault scope, then the row refreshes and (once
      // both are set) Authorize appears.
      var det=document.createElement("details");det.className="gapp";if(!a.clientReady)det.open=true;
      var sum=document.createElement("summary");sum.textContent=a.clientReady?"Replace app credentials":"Set app credentials";det.appendChild(sum);
      var l1=document.createElement("label");l1.textContent="Client ID";det.appendChild(l1);
      var cid=document.createElement("input");cid.type="text";cid.placeholder="…apps.googleusercontent.com";cid.autocomplete="off";det.appendChild(cid);
      var l2=document.createElement("label");l2.textContent="Client secret";det.appendChild(l2);
      var csec=document.createElement("input");csec.type="password";csec.placeholder="GOCSPX-…";csec.autocomplete="off";det.appendChild(csec);
      var actions=document.createElement("div");actions.className="ing-row";actions.style.marginTop="8px";
      var sbtn=document.createElement("button");sbtn.className="ing-go";sbtn.textContent="Save app";
      var msg=document.createElement("span");msg.className="ksst";
      actions.appendChild(sbtn);actions.appendChild(msg);det.appendChild(actions);
      sbtn.addEventListener("click",function(){
        var idv=cid.value.trim(),scv=csec.value.trim();
        if(!idv||!scv){msg.className="ksst r";msg.textContent="both fields needed";return;}
        sbtn.disabled=true;msg.className="ksst";msg.textContent="saving…";
        post("/api/cfg/secret",{business:a.account,name:"google_client_id",value:idv}).then(function(r1){
          if(!r1.ok){sbtn.disabled=false;msg.className="ksst r";msg.textContent=(r1.j&&r1.j.error)||"id failed";return;}
          post("/api/cfg/secret",{business:a.account,name:"google_client_secret",value:scv}).then(function(r2){
            if(!r2.ok){sbtn.disabled=false;msg.className="ksst r";msg.textContent=(r2.j&&r2.j.error)||"secret failed";return;}
            loadGoogleStatus(wrap);                        // refresh: Authorize should now appear
          });
        });
      });
      block.appendChild(det);
      wrap.appendChild(block);
    });
  }).catch(function(){wrap.innerHTML="<div class='n'>(couldn't check Google connections)</div>";});
}
function authorizeGoogle(account,btn,wrap){
  var old=btn.textContent;btn.disabled=true;btn.textContent="opening…";
  post("/api/google/authurl",{account:account}).then(function(r){
    if(!(r.ok&&r.j&&r.j.url)){btn.disabled=false;btn.textContent=old;
      alert((r.j&&r.j.error)||"couldn't start authorization");return;}
    window.open(r.j.url,"_blank","noopener");
    btn.textContent="finish in the tab…";
    var tries=0,iv=setInterval(function(){tries++;
      api("/api/google/status").then(function(s){
        var accs=(s.ok&&s.j&&s.j.accounts)||[];
        var a=accs.filter(function(x){return x.account===account;})[0];
        if(a&&a.connected){clearInterval(iv);loadGoogleStatus(wrap);}
      });
      if(tries>90){clearInterval(iv);btn.disabled=false;btn.textContent=old;}
    },2000);
  }).catch(function(){btn.disabled=false;btn.textContent=old;});
}
// ---- GitHub: one field, paste the token, see it connect ----
function renderGithubPane(card){
  var wrap=document.createElement("div");wrap.className="keystat";card.appendChild(wrap);
  var lab=document.createElement("label");lab.textContent="Personal access token";card.appendChild(lab);
  var inp=document.createElement("input");inp.type="password";inp.placeholder="github_pat_… or ghp_…";inp.autocomplete="off";card.appendChild(inp);
  var actions=document.createElement("div");actions.className="ing-row";actions.style.marginTop="8px";
  var btn=document.createElement("button");btn.className="ing-go";btn.textContent="Save token";
  var msg=document.createElement("span");msg.className="ksst";
  actions.appendChild(btn);actions.appendChild(msg);card.appendChild(actions);
  btn.addEventListener("click",function(){var v=inp.value.trim();
    if(!v){msg.className="ksst r";msg.textContent="paste a token";return;}
    btn.disabled=true;msg.className="ksst";msg.textContent="saving…";
    post("/api/cfg/secret",{business:"system",name:"github_token",value:v}).then(function(r){btn.disabled=false;
      if(r.ok){inp.value="";msg.className="ksst g";msg.textContent="saved";loadGithubStatus(wrap);}
      else{msg.className="ksst r";msg.textContent=(r.j&&r.j.error)||"failed";}});});
  loadGithubStatus(wrap);
}
function loadGithubStatus(wrap){
  wrap.innerHTML="<div class='n'>checking GitHub…</div>";
  api("/api/github/status").then(function(r){wrap.innerHTML="";
    var d=(r.ok&&r.j)||{};
    var cls=d.connected?"g":(d.stored?"r":"o");
    var repos=d.repos||[];
    var st=d.connected?("connected · "+repos.length+" repos"):(d.stored?("token stored but "+(d.error||"rejected")):"no token yet");
    var row=document.createElement("div");row.className="ksrow";
    var dot=document.createElement("span");dot.className="dot "+cls;
    var nm=document.createElement("span");nm.className="ksname";nm.textContent="github";
    var sv=document.createElement("span");sv.className="ksst "+cls;sv.textContent=st;
    row.appendChild(dot);row.appendChild(nm);row.appendChild(sv);wrap.appendChild(row);
    if(d.connected&&repos.length){var rl=document.createElement("div");rl.className="n";rl.style.padding="4px 10px 2px";
      rl.textContent="reachable: "+repos.slice(0,8).join(", ")+(repos.length>8?" …":"");wrap.appendChild(rl);}
  }).catch(function(){wrap.innerHTML="<div class='n'>(couldn't check GitHub)</div>";});
}
document.getElementById("gear").addEventListener("click",openSettings);
document.getElementById("settingsClose").addEventListener("click",closeSettings);

// ---- ingestion review: learn one item at a time ----
function ingestBusinesses(){return (cfgState&&cfgState.businesses)||[];}
function bizTitle(slug){return (cfgState&&cfgState.businessTitles&&cfgState.businessTitles[slug])||slug;}
var lastIngestBiz="";   // remember the last "File into" pick so bulk-routing (e.g. a whole repo into Rosco's Vault) is Enter, Enter, Enter
function setIngestPip(n){ingCount=n;var pip=document.getElementById("ingestPip");if(pip)pip.style.display=n>0?"inline-block":"none";
  var ib=document.querySelector(".ingbanner");if((ib?1:0)!==(n>0?1:0)&&document.getElementById("qwrap"))loadQueue();}
function pollIngestPip(){api("/api/ingest/queue").then(function(r){setIngestPip(((r.ok&&r.j&&r.j.items)||[]).length);});}
function openIngest(){document.getElementById("ingest").style.display="flex";
  api("/api/cfg/state").then(function(r){if(r.ok&&r.j&&r.j.businesses)cfgState=r.j;loadIngest();});}
function closeIngest(){document.getElementById("ingest").style.display="none";}
function loadIngest(){
  var host=document.getElementById("ingestBody");host.innerHTML="";
  var add=document.createElement("div");add.className="ing-add";
  var ta=document.createElement("textarea");ta.placeholder="Paste notes, a doc, an email — Rosco splits it into items and proposes where each goes. Nothing is learned until you say so.";
  var addBtn=document.createElement("button");addBtn.className="ing-go";addBtn.textContent="Queue items";addBtn.style.alignSelf="flex-start";
  addBtn.addEventListener("click",function(){var t=ta.value.trim();if(!t)return;
    addBtn.disabled=true;addBtn.textContent="reading…";
    post("/api/ingest/add",{text:t}).then(function(r){addBtn.disabled=false;addBtn.textContent="Queue items";
      if(r.ok){ta.value="";loadIngest();}else alert((r.j&&r.j.error)||"couldn't queue");});});
  add.appendChild(ta);add.appendChild(addBtn);host.appendChild(add);
  // or pull a Google Drive file's contents straight into the queue
  var drow=document.createElement("div");drow.className="ing-row";
  var dl=document.createElement("label");dl.textContent="or Drive file";drow.appendChild(dl);
  var din=document.createElement("input");din.type="text";din.placeholder="file name, e.g. DECISIONS.md";din.autocomplete="off";
  din.style.cssText="flex:1;min-width:150px;background:var(--ground);border:1px solid var(--line-hot);color:var(--text);font:12.5px/1 var(--sans);padding:8px";
  var dbtn=document.createElement("button");dbtn.className="ing-go";dbtn.textContent="Pull from Drive";
  var dmsg=document.createElement("span");dmsg.className="ksst";
  dbtn.addEventListener("click",function(){var nm=din.value.trim();if(!nm)return;
    dbtn.disabled=true;dmsg.className="ksst";dmsg.textContent="reading Drive…";
    post("/api/ingest/drive",{name:nm}).then(function(r){dbtn.disabled=false;
      if(r.ok){din.value="";dmsg.className="ksst g";dmsg.textContent="queued "+r.j.added+" from "+(r.j.file||nm);loadIngest();}
      else{dmsg.className="ksst r";dmsg.textContent=(r.j&&r.j.error)||"couldn't pull";}});});
  drow.appendChild(din);drow.appendChild(dbtn);drow.appendChild(dmsg);host.appendChild(drow);
  // or pull a file from a GitHub repo (needs a github_token stored)
  var grow=document.createElement("div");grow.className="ing-row";
  var gl=document.createElement("label");gl.textContent="or GitHub";grow.appendChild(gl);
  var grepo=document.createElement("input");grepo.type="text";grepo.placeholder="repo, e.g. Rosco-v1";grepo.autocomplete="off";
  grepo.style.cssText="flex:1;min-width:110px;background:var(--ground);border:1px solid var(--line-hot);color:var(--text);font:12.5px/1 var(--sans);padding:8px";
  var gpath=document.createElement("input");gpath.type="text";gpath.placeholder="path, or blank = whole repo";gpath.autocomplete="off";
  gpath.style.cssText=grepo.style.cssText;
  var gbtn=document.createElement("button");gbtn.className="ing-go";gbtn.textContent="Pull from GitHub";
  var gmsg=document.createElement("span");gmsg.className="ksst";
  gbtn.addEventListener("click",function(){var rp=grepo.value.trim(),pt=gpath.value.trim();if(!rp)return;
    gbtn.disabled=true;gmsg.className="ksst";gmsg.textContent=pt?"reading GitHub…":"downloading the repo…";
    post("/api/ingest/github",{repo:rp,path:pt}).then(function(r){gbtn.disabled=false;
      if(r.ok){gpath.value="";gmsg.className="ksst g";gmsg.textContent="queued "+r.j.added+" from "+(r.j.file||rp);loadIngest();}
      else{gmsg.className="ksst r";gmsg.textContent=(r.j&&r.j.error)||"couldn't pull";}});});
  grow.appendChild(grepo);grow.appendChild(gpath);grow.appendChild(gbtn);grow.appendChild(gmsg);host.appendChild(grow);
  Promise.all([api("/api/ingest/queue"),api("/api/ingest/readiness")]).then(function(res){
    var q=(res[0].ok&&res[0].j&&res[0].j.items)||[];
    var rd=(res[1].ok&&res[1].j)||{};
    setIngestPip(q.length);
    if(rd.confident&&q.length){
      var rb=document.createElement("div");rb.className="ing-ready";
      var msg=document.createElement("span");msg.textContent="Rosco has been placing these well lately ("+Math.round((rd.recentRate||0)*100)+"% on target). Auto-route the rest?";
      var ab=document.createElement("button");ab.className="ing-go";ab.textContent="Auto-route "+q.length;
      ab.addEventListener("click",function(){ab.disabled=true;autoRoute(q);});
      rb.appendChild(msg);rb.appendChild(ab);host.appendChild(rb);
    }
    var bar=document.createElement("div");bar.className="ing-bar";
    var l=document.createElement("span");l.textContent=q.length+" waiting";
    var rt=document.createElement("span");rt.textContent=(rd.decided||0)+" placed · "+Math.round((rd.rate||0)*100)+"% on target";
    bar.appendChild(l);bar.appendChild(rt);
    if(q.length){var cl=document.createElement("button");cl.className="ing-clear";cl.textContent="Clear queue";
      cl.addEventListener("click",function(){
        if(!confirm("Skip all "+q.length+" pending item(s)? They stay on the log as history but leave the queue, so you can re-ingest cleanly.")) return;
        cl.disabled=true;cl.textContent="clearing…";
        post("/api/ingest/clear",{}).then(function(r){ if(r.ok){loadIngest();}
          else{cl.disabled=false;cl.textContent="Clear queue";alert((r.j&&r.j.error)||"couldn't clear");} })
          .catch(function(){cl.disabled=false;cl.textContent="Clear queue";alert("server unreachable");});});
      bar.appendChild(cl);}
    host.appendChild(bar);
    if(!q.length){var e=document.createElement("div");e.className="ing-empty";e.textContent="Nothing to review. Paste something above to begin.";host.appendChild(e);return;}
    host.appendChild(ingestCard(q[0]));
  });
}
function ingestCard(item){
  var card=document.createElement("div");card.className="ing-card";
  var txt=document.createElement("div");txt.className="ing-text";txt.textContent=item.text;card.appendChild(txt);
  var shorthand=item.summary||"";   // the distilled form that actually gets learned (not the raw text)
  var rd=document.createElement("div");rd.className="ing-reads";
  rd.innerHTML="<span class='rl'>Rosco's shorthand (this is what gets learned)</span> <span class='rv'>"+(item.summary?esc(item.summary):"distilling…")+"</span>";
  card.appendChild(rd);
  if(!item.summary){post("/api/ingest/read",{text:item.text}).then(function(r){
    var v=rd.querySelector(".rv");if(!v)return;
    if(r.ok&&r.j&&r.j.summary){shorthand=r.j.summary;v.textContent=r.j.summary;}
    else{v.textContent="(couldn't read — "+esc((r.j&&(r.j.why||r.j.error))||"no reason given")+")";}
  }).catch(function(){var v=rd.querySelector(".rv");if(v)v.textContent="(couldn't read — server unreachable)";});}
  var prop=document.createElement("div");prop.className="ing-prop";
  if(item.business){var s1=document.createElement("span");s1.textContent="Rosco →";
    var b=document.createElement("b");b.textContent=bizTitle(item.business);
    var s2=document.createElement("span");s2.textContent=Math.round((item.confidence||0)*100)+"% · "+(item.why||"");
    prop.appendChild(s1);prop.appendChild(b);prop.appendChild(s2);
  } else {var s0=document.createElement("span");s0.textContent="Rosco isn't sure — you place this one";prop.appendChild(s0);}
  card.appendChild(prop);
  var row=document.createElement("div");row.className="ing-row";
  var lab=document.createElement("label");lab.textContent="File into";row.appendChild(lab);
  var sel=document.createElement("select");
  var ingDef=lastIngestBiz||item.business;   // last pick wins, so a run of code chunks stays on Rosco's Vault
  ingestBusinesses().forEach(function(bz){var o=document.createElement("option");o.value=bz;o.textContent=bizTitle(bz);if(bz===ingDef)o.selected=true;sel.appendChild(o);});
  row.appendChild(sel);
  var go=document.createElement("button");go.className="ing-go";go.textContent="Ingest here";
  go.addEventListener("click",function(){lastIngestBiz=sel.value;decideIngest(item.cand,sel.value,"ingest",card,shorthand);});
  var skip=document.createElement("button");skip.className="ing-skip";skip.textContent="Skip";
  skip.addEventListener("click",function(){decideIngest(item.cand,"","skip",card);});
  row.appendChild(go);row.appendChild(skip);card.appendChild(row);
  // Keyboard review: Tab cycles File-into → Ingest → Skip, Enter accepts the
  // highlighted action, Esc drops focus. On the select, Enter stays native so a
  // business pick commits before anything ingests. A confident item lands on
  // Ingest so Enter files it; an unsure one lands on the picker to choose first.
  var controls=[sel,go,skip];
  card.addEventListener("keydown",function(e){
    if(e.key==="Tab"){e.preventDefault();
      var i=controls.indexOf(document.activeElement),dir=e.shiftKey?-1:1;
      controls[(i+dir+controls.length)%controls.length].focus();
    } else if(e.key==="Enter"){
      if(document.activeElement===go){e.preventDefault();go.click();}
      else if(document.activeElement===skip){e.preventDefault();skip.click();}
    } else if(e.key==="Escape"&&document.activeElement&&document.activeElement.blur){
      document.activeElement.blur();
    }
  });
  setTimeout(function(){((lastIngestBiz||item.business)?go:sel).focus();},0);
  return card;
}
function decideIngest(cand,business,action,card,shorthand){
  if(card)card.querySelectorAll("button,select").forEach(function(x){x.disabled=true;});
  post("/api/ingest/decide",{cand:cand,business:business,action:action,shorthand:shorthand||""}).then(function(r){
    if(r.ok){loadIngest();}
    else{alert((r.j&&r.j.error)||"couldn't decide");if(card)card.querySelectorAll("button,select").forEach(function(x){x.disabled=false;});}
  });
}
function autoRoute(items){var withBiz=items.filter(function(x){return x.business;});var i=0;
  (function next(){if(i>=withBiz.length){loadIngest();return;}var it=withBiz[i++];
    post("/api/ingest/decide",{cand:it.cand,business:it.business,action:"ingest"}).then(next,next);})();}
document.getElementById("ingestBtn").addEventListener("click",openIngest);
document.getElementById("ingestClose").addEventListener("click",closeIngest);

// ---- resizable right panel: slide the context/chat split (up-down) and the
// whole panel's width (left-right). Both handles use the same drag scaffold.
(function(){
  var right=document.getElementById("rightpane"),ctx=document.getElementById("ctx"),
      vh=document.getElementById("vhandle"),hh=document.getElementById("hhandle");
  function save(k,v){try{localStorage.setItem(k,v);}catch(e){}}
  function load(k){try{return parseFloat(localStorage.getItem(k));}catch(e){return NaN;}}
  // Restore the split/width the way Ross last dragged them — persisted below, so
  // the chat window keeps its size across reloads and new sessions.
  var sh=load("rosco.ctxH");
  if(ctx&&sh>=70){ctx.style.flex="none";ctx.style.height=sh+"px";}
  var sw=load("rosco.rightW");
  if(right&&sw>=280){right.style.width=Math.min(sw,window.innerWidth-340)+"px";}
  function onDrag(handle,move){
    if(!handle)return;
    handle.addEventListener("mousedown",function(e){e.preventDefault();
      document.body.style.userSelect="none";document.body.style.cursor=getComputedStyle(handle).cursor;
      function mm(ev){move(ev);}
      function up(){window.removeEventListener("mousemove",mm);window.removeEventListener("mouseup",up);
        document.body.style.userSelect="";document.body.style.cursor="";}
      window.addEventListener("mousemove",mm);window.addEventListener("mouseup",up);});
  }
  onDrag(vh,function(e){if(!right||!ctx)return;var r=right.getBoundingClientRect();
    var h=Math.max(70,Math.min(r.height-140,e.clientY-r.top));
    ctx.style.flex="none";ctx.style.height=h+"px";save("rosco.ctxH",h);});
  onDrag(hh,function(e){if(!right)return;
    var w=Math.max(280,Math.min(window.innerWidth-340,window.innerWidth-e.clientX));
    right.style.width=w+"px";save("rosco.rightW",w);
    if(typeof resize==="function")resize();});   // graph canvas re-measures on width change
})();

// Ambient pulses are just idle liveness now - real activity drives the graph
// through loadActivity(), so keep the timer slow and let the log do the talking.
resize();if(!reduce)setInterval(fire,3200);requestAnimationFrame(frame);
