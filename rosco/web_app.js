"use strict";
var CSRF="", TYPEC={agent:"#c9a227",person:"#5b8fb0",site:"#4ea86e",tool:"#37b0a0",core:"#e8efeb"};

function api(path){return fetch(path,{headers:{"Accept":"application/json"}}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});});}
function post(path,body){return fetch(path,{method:"POST",headers:{"Content-Type":"application/json","X-Rosco-CSRF":CSRF},body:JSON.stringify(body||{})}).then(function(r){return r.json().then(function(j){return{ok:r.ok,j:j};});});}

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

// if a prior session cookie is still good, /api/overview will say unlocked
api("/api/overview").then(function(res){ if(res.j&&res.j.unlocked){ /* still need CSRF; ask to re-unlock */ } });

// ---- boot the live console ----
var seenAct={}, actFirst=true;
function boot(){ refreshHud(); loadQueue(); loadMesh();
  setInterval(refreshHud,8000); setInterval(loadQueue,15000);
  setInterval(loadActivity,4000); setTimeout(loadActivity,1200); }

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
function loadQueue(){ api("/api/queue").then(function(res){
  var q=(res.ok&&Array.isArray(res.j))?res.j:[];
  markWaiting(q);                       // ring captains even while a node is shown
  var el=document.getElementById("qwrap"),rh=document.getElementById("rhead");
  if(!el||!rh) return;                  // a node's context is showing; queue is hidden
  rh.textContent="Waiting on you · "+q.length;
  if(!q.length){el.innerHTML="<div class='empty'>Nothing waiting. You're clear.</div>";return;}
  el.innerHTML=q.map(askCard).join("");
  q.forEach(function(a){ wireCard(a.id); });
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

function loadMesh(){ api("/api/mesh").then(function(res){
  var m=(res.ok&&res.j&&res.j.nodes)?res.j:{nodes:[],edges:[]};
  byId={};N=m.nodes.map(function(n,i){byId[n.id]=i;
    return {id:n.id,label:n.label,type:n.type,rank:n.rank,biz:n.business,reports:n.reports,
      x:(Math.random()-.5)*1.6,y:(Math.random()-.5)*1.6,z:(Math.random()-.5)*1.6,
      vx:0,vy:0,vz:0,r:n.type==="agent"?(n.rank==="Chief of Staff"?16:n.rank==="Commander"?14:n.rank==="Captain"?10:6.5):8,
      core:(n.label==="Rosco"||n.label==="Ross"),links:0,pulse:0,tw:Math.random()*6.28};});
  E=m.edges.map(function(e){return[byId[e.a],byId[e.b],e.kind];}).filter(function(e){return e[0]!=null&&e[1]!=null;});
  E.forEach(function(e){N[e[0]].links++;N[e[1]].links++;});
  layout(); if(N.length){ selected=byId["Rosco"]!=null?byId["Rosco"]:0; }
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
function project(r){var fov=3.4,scale=Math.min(W,H)*.42,f=fov/(fov+r.z);return{x:W/2+r.x*scale*f,y:H/2+r.y*scale*f,f:f,z:r.z};}
function fire(){if(!E.length)return;var e=E[(Math.random()*E.length)|0];signals.push({from:e[0],to:e[1],t:0,sp:.012+Math.random()*.014});}

function frame(){var T=performance.now();
  if(auto&&!drag)tYaw+=.0015;yaw+=(tYaw-yaw)*.08;pitch+=(tPitch-pitch)*.08;ctx.clearRect(0,0,W,H);
  for(var i=0;i<N.length;i++){var r=rot(N[i]),p=project(r);N[i].px=p.x;N[i].py=p.y;N[i].pf=p.f;N[i].pz=r.z;
    N[i].pr=N[i].r*p.f*(1+Math.min(N[i].links,10)*.03);if(N[i].pulse>0)N[i].pulse*=.94;}
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
    var tw=.82+.18*Math.sin(T/650+n.tw),spr=sprite[n.core?"core":n.type]||sprite.agent,gs=base*(3.4+glow*3)*(hi?1.3:1);
    ctx.globalAlpha=(dim?.1:.55*k2)*tw;ctx.drawImage(spr,n.px-gs,n.py-gs,gs*2,gs*2);
    ctx.globalCompositeOperation="source-over";ctx.globalAlpha=dim?.3:1;
    ctx.beginPath();ctx.arc(n.px,n.py,Math.max(1.2,base*(hi?1.25:1)),0,7);ctx.fillStyle=dim?"#3a4640":col;ctx.fill();
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
    +(n.biz?"<div class='kv'><div class='k'>Business</div><div class='v'>"+esc(n.biz)+"</div></div>":"")
    +(n.reports?"<div class='kv'><div class='k'>Reports to</div><div class='v'>"+esc(n.reports)+"</div></div>":"")
    +(links?"<div class='kv'><div class='k'>Linked</div><div class='v' style='display:flex;flex-wrap:wrap;gap:5px'>"+links+"</div></div>":"")
    +"</div>";
  document.getElementById("back").addEventListener("click",restoreQueue);
  ctx.querySelectorAll("[data-jump]").forEach(function(el){el.addEventListener("click",function(){
    var i=byId[el.getAttribute("data-jump")]; if(i!=null){selected=i;N[i].pulse=1;showNode(N[i]);}});});
}
function restoreQueue(){
  document.getElementById("ctx").innerHTML=
    "<div class='rhead' id='rhead'>Waiting on you</div><div class='qwrap' id='qwrap'></div>";
  loadQueue();
}

// ---- tools rail (navigation stubs for now) ----
var TOOLS=[["Mesh","M12 3v4M12 17v4M3 12h4M17 12h4M12 8a4 4 0 100 8 4 4 0 000-8z"],
  ["Queue","M4 6h16M4 12h16M4 18h10"],["People","M9 11a3 3 0 100-6 3 3 0 000 6zm7 8a7 7 0 00-14 0"],
  ["Tools","M14 7l3 3-8 8-3-3zM3 21l4-1"],["Spend","M4 18l5-6 4 4 7-9"],["Verify","M20 6L9 17l-5-5"]];
var tel=document.getElementById("tools");
TOOLS.forEach(function(t,i){var el=document.createElement("div");el.className="tool"+(i===0?" on":"");
  el.innerHTML="<svg viewBox='0 0 24 24'><path d='"+t[1]+"'/></svg><span class='t'>"+t[0]+"</span>";
  el.addEventListener("click",function(){tel.querySelectorAll(".tool").forEach(function(x){x.classList.remove("on");});el.classList.add("on");});
  tel.appendChild(el);});

// ---- chat with Rosco ----
function bubble(cls,by,text){var m=document.createElement("div");m.className="msg "+cls;
  var b=document.createElement("div");b.className="by";b.textContent=by;
  var d=document.createElement("div");d.className="bub";d.textContent=text;
  m.appendChild(b);m.appendChild(d);var s=document.getElementById("stream");
  s.appendChild(m);s.scrollTop=s.scrollHeight;return m;}
function sendChat(){
  var inp=document.getElementById("chatin"),btn=document.getElementById("chatsend");
  var msg=inp.value.trim(); if(!msg) return;
  bubble("you","Ross",msg); inp.value=""; btn.disabled=true;
  var waiting=bubble("wait","Rosco","thinking…");
  post("/api/chat",{message:msg}).then(function(res){
    waiting.remove(); btn.disabled=false; inp.focus();
    if(res.ok){ bubble("ros","Rosco", res.j.reply||"…"); }
    else{ bubble("ros","Rosco", (res.j&&res.j.error)||"couldn't reach the model."); }
  }).catch(function(){ waiting.remove(); btn.disabled=false;
    bubble("ros","Rosco","server unreachable."); });
}
document.getElementById("chatsend").addEventListener("click",sendChat);
document.getElementById("chatin").addEventListener("keydown",function(e){if(e.key==="Enter")sendChat();});

// ---- settings: the CLI's config commands, as forms ----
var CFG=[
 {t:"Models",a:"model",n:"Pick a role, a provider, then a model your key can serve.",
  f:[{k:"role",l:"Role",sel:"roles"},{k:"provider",l:"Provider",sel:"providers"},{k:"model",l:"Model",dyn:"models"}]},
 {t:"API keys",a:"secret",n:"Stored encrypted in the vault. Never shown again.",
  f:[{k:"name",l:"Key name",ph:"openrouter_api_key"},{k:"value",l:"Value",type:"password"}]},
 {t:"Spend cap",a:"budget",n:"A soft monthly cap. Warns at 80% and 100%; never blocks.",
  f:[{k:"scope",l:"Scope (* = all)",ph:"*"},{k:"usd",l:"Monthly $",ph:"200"}]},
 {t:"Teach a business",a:"ingest",n:"Paste a doc to load as lessons, or leave blank to load the starter facts.",
  f:[{k:"business",l:"Business",sel:"businesses"},{k:"text",l:"Doc (optional)",type:"textarea"}]},
 {t:"Enrol a person",a:"enrol",n:"Telegram/chat prove identity; email/phone are treated as spoofable.",
  f:[{k:"person",l:"Name",ph:"brent"},{k:"channel",l:"Channel",opt:["telegram","chat","email","phone"]},{k:"address",l:"Address or id",ph:"8481123"}]},
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
  if(field.sel && Array.isArray(cfgState[field.sel])) return cfgState[field.sel];
  return null;
}
function buildForms(){var host=document.getElementById("cfgForms");host.innerHTML="";
  CFG.forEach(function(sec){
    var card=document.createElement("div");card.className="cfg";
    var h=document.createElement("h4");h.textContent=sec.t;card.appendChild(h);
    if(sec.n){var nn=document.createElement("div");nn.className="n";nn.textContent=sec.n;card.appendChild(nn);}
    var inputs={},dyn={};
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
      var fillModels=function(){
        wrap.innerHTML="<div class='n'>loading models…</div>";
        api("/api/cfg/models?provider="+encodeURIComponent(inputs.provider.value)).then(function(r){
          wrap.innerHTML="";
          var ids=(r.ok&&r.j&&r.j.models)||[];
          if(ids.length){var sel=document.createElement("select");
            ids.forEach(function(id){var o=document.createElement("option");o.value=id;o.textContent=id;sel.appendChild(o);});
            wrap.appendChild(sel);inputs.model=sel;
          } else {var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";inp.autocomplete="off";
            wrap.appendChild(inp);inputs.model=inp;
            if(r.j&&r.j.error){var e=document.createElement("div");e.className="n";e.textContent=esc(r.j.error);wrap.appendChild(e);}
          }
        }).catch(function(){wrap.innerHTML="";var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";wrap.appendChild(inp);inputs.model=inp;});
      };
      inputs.provider.addEventListener("change",fillModels); fillModels();
    }
    var btn=document.createElement("button");btn.className="go";btn.textContent="Apply";
    var res=document.createElement("div");res.className="res";
    btn.addEventListener("click",function(){
      var body={};for(var k in inputs){body[k]=inputs[k]?inputs[k].value:"";}
      if(body.businesses!==undefined) body.businesses=body.businesses.split(",").map(function(x){return x.trim();}).filter(Boolean);
      btn.disabled=true;res.className="res";res.textContent="working…";
      post("/api/cfg/"+sec.a,body).then(function(r){btn.disabled=false;
        if(r.ok){res.className="res ok";res.textContent=r.j.msg||"done";
          if(inputs.value)inputs.value.value="";               // never keep a secret in the field
          api("/api/cfg/state").then(function(x){cfgState=(x.ok&&x.j)?x.j:cfgState;renderState();});
        } else {res.className="res err";res.textContent=(r.j&&r.j.error)||"failed";}
      }).catch(function(){btn.disabled=false;res.className="res err";res.textContent="server unreachable";});
    });
    card.appendChild(btn);card.appendChild(res);host.appendChild(card);
  });
}
document.getElementById("gear").addEventListener("click",openSettings);
document.getElementById("settingsClose").addEventListener("click",closeSettings);

// Ambient pulses are just idle liveness now - real activity drives the graph
// through loadActivity(), so keep the timer slow and let the log do the talking.
resize();if(!reduce)setInterval(fire,3200);requestAnimationFrame(frame);
