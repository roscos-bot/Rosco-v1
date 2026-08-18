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
  refreshHud(); loadGates(); loadMesh(); pollIngestPip();
  if(booted)return; booted=true;                            // re-unlock must not stack a 2nd set of timers
  setInterval(refreshHud,8000); setInterval(loadGates,15000);
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

// ---- the "Needs you" surface: GATES in the always-on pane, the full band+lanes
//      in the drawer. Ranking + sensitivity are decided server-side (/api/needs),
//      because a security-relevant sort must not be gameable from a browser tab. ----
var ingCount=0;                          // pending ingest items, kept fresh by the pip poll
// The always-visible pane shows the GATES band (grants + sensitive requests) only —
// the 'is anyone blocked on me?' question. Cheap /api/needs poll: pure log replay,
// no Google, no model. Email/docs/tasks live one click away in the drawer.
function loadGates(){ api("/api/needs").then(function(res){
  var d=(res.ok&&res.j)?res.j:{band:[],lanes:{},counts:{}};
  var band=d.band||[], c=d.counts||{};
  markWaiting(band.filter(function(b){return b.kind==="grant";}));   // ring captains even while a node is shown
  setNeedsBadge(c.gates||0,c.work||0,!!c.sensitive);
  var el=document.getElementById("qwrap"),rh=document.getElementById("rhead");
  if(!el||!rh) return;                  // a node's context is showing; pane is hidden
  if(cardBusy(el)) return;              // don't wipe a gate Ross is mid-decision on — retry next poll
  var g=c.gates||0;
  rh.innerHTML="Needs you"+(g?(" · <b"+(c.sensitive?" style='color:var(--red)'":"")+">"+g+"</b>"):"");
  el.innerHTML="";
  if(g){ renderBand(el,band);
    if(c.bandOverflow>0){var mo=document.createElement("div");mo.className="empty";mo.textContent="+"+c.bandOverflow+" more gates in the drawer";el.appendChild(mo);}
  } else { el.appendChild(gatesEmpty(d.ledgerDigest||[])); }
  el.appendChild(needsOpener(c.work||0));   // the way into email / docs / tasks
});}
// Render a band (grants + sensitive requests) into a container, in P order, wiring
// each grant AFTER it's in the DOM (wireCard looks it up by data-id). Shared by the
// pane and the drawer.
function renderBand(el,band){   // the band is grants only (requests are never banded)
  band.forEach(function(it){
    var w=document.createElement("div");w.innerHTML=askCard(it);var card=w.firstChild;el.appendChild(card);wireCard(card);
  });
}
// The cheap pane poll never looks at email, so the opener must NOT claim the
// inbox is clear — it can only speak to docs/tasks it actually counted. Email is
// only surfaced (and counted) inside the drawer's full fetch.
// Is Ross actively deciding a gate inside this container? A background re-render
// (the 15s poll, or a drawer refresh) must not blow away a card that holds live
// state: a half-typed deny-why note, a ticked sensitive-ack, or keyboard focus
// inside a grant card. If so, skip the rebuild and catch it on the next tick.
function cardBusy(el){
  if(!el)return false;
  var cards=el.querySelectorAll(".ask"), a=document.activeElement;
  for(var i=0;i<cards.length;i++){var c=cards[i];
    var vd=c.querySelector(".verdict");
    if(vd&&vd.style.display!=="none")continue;         // already answered — not busy
    if(c.querySelector(".deny-why[style*='block']"))return true;
    if(c.querySelector(".sens-chk:checked"))return true;
    if(a&&c.contains(a))return true;                   // focus/typing inside an unanswered gate
  }
  return false;
}
function needsOpener(work){
  var op=document.createElement("div");op.className="needs-open";
  op.innerHTML="<span>"+(work>0?(work+" waiting to review"):"Your inbox, docs &amp; tasks")+"</span><b>Open Needs you →</b>";
  op.addEventListener("click",openNext);
  return op;
}
// The empty/verify moment: nobody's blocked — so show what Rosco DID (trust but
// verify), from the honest log, instead of a dead "nothing here".
function gatesEmpty(digest){
  var box=document.createElement("div");box.className="empty gates-clear";
  if(!digest||!digest.length){box.textContent="Nothing waiting. You're clear.";return box;}
  var h=document.createElement("div");h.className="gc-h";h.textContent="You're clear. Recently, Rosco:";box.appendChild(h);
  digest.slice(0,5).forEach(function(r){var li=document.createElement("div");li.className="gc-li";
    li.textContent="· "+(r.by||"Rosco")+" "+(r.what||"");box.appendChild(li);});
  var lk=document.createElement("button");lk.className="gc-link";lk.textContent="See the full ledger →";
  lk.addEventListener("click",function(){showTool("Ledger");});box.appendChild(lk);
  return box;
}

// Ring the captain of any business with a grant-ask waiting on Ross. The captain
// is the agent node for that business that reports to Rosco.
function markWaiting(grants){
  var wanted={}; (grants||[]).forEach(function(a){ wanted[a.business]=1; });
  N.forEach(function(n){
    n.waiting = (n.type==="agent" && n.reports==="Rosco" && wanted[n.business]) ? 1 : 0;
  });
}
function esc(s){return (s==null?"":""+s).replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;").replace(/"/g,"&quot;").replace(/'/g,"&#39;");}
// The grant gate. Sensitivity is now the SERVER'S call (a.sensitive, from
// capabilities.is_sensitive) — not a client guess. Two frictions the old card
// lacked: (1) Deny opens a "why" note the server already stores as the grant's
// reason — the learning signal that stops the ask coming back; (2) a SENSITIVE
// gate disables Allow until Ross ticks "I've read this" — sort-first, act-slowest.
function askCard(a){
  var sens=!!a.sensitive;
  return "<div class='ask"+(sens?" sens":"")+"' data-id='"+esc(a.id)+"'>"
    +"<div class='top'><span class='who'>"+esc(a.person)+"</span>"
    +"<span class='cap'>"+esc(a.business)+":"+esc(a.capability)+"</span>"
    +"<span class='verb"+(a.verb==="do"?" do":"")+"'>"+esc((a.verb||"").toUpperCase())+"</span>"
    +(sens?"<span class='verb sensflag'>SENSITIVE</span>":"")+"</div>"
    +"<div class='said'>"+esc(a.detail)+"</div>"
    +(sens?"<label class='sens-ack'><input type='checkbox' class='sens-chk'> I've read this sensitive request</label>":"")
    +"<div class='acts'>"
    +"<button class='btn ga' data-v='allow-once'>Allow once</button>"
    +"<button class='btn ga solid' data-v='allow-always'>Allow always</button>"
    +"<button class='btn da deny-open'>Deny…</button>"
    +"</div>"
    +"<div class='deny-why' style='display:none'>"
      +"<textarea class='deny-note' placeholder='Why? Optional — but it teaches Rosco to stop asking.'></textarea>"
      +"<div class='deny-row'>"
        +"<button class='btn da' data-v='deny-once'>Deny once</button>"
        +"<button class='btn da solid' data-v='deny-always'>Deny always</button>"
      +"</div></div>"
    +"<div class='verdict' style='display:none'></div></div>";
}
// `card` is the ELEMENT (not an id): the same grant renders in BOTH the pane and
// the drawer band with the same data-id, so a global document.querySelector would
// wire only the first copy and leave the other dead. Scope everything to the node.
function wireCard(card){
  if(typeof card==="string"){card=document.querySelector(".ask[data-id='"+card+"']");}
  if(!card)return;
  var id=card.getAttribute("data-id");
  var chk=card.querySelector(".sens-chk"), allow=card.querySelectorAll(".btn.ga");
  if(chk){                              // sensitive: Allow is disabled until acknowledged
    allow.forEach(function(b){b.disabled=true;});
    chk.addEventListener("change",function(){allow.forEach(function(b){b.disabled=!chk.checked;});});
  }
  var open=card.querySelector(".deny-open"), why=card.querySelector(".deny-why");
  if(open&&why){open.addEventListener("click",function(){
    var show=why.style.display==="none";why.style.display=show?"block":"none";
    if(show){var ta=why.querySelector(".deny-note");if(ta)ta.focus();}});}
  card.querySelectorAll(".btn[data-v]").forEach(function(b){ b.addEventListener("click",function(){
    var v=b.getAttribute("data-v");
    var note="";var ta=card.querySelector(".deny-note");
    if(ta&&v.indexOf("deny")===0)note=ta.value.trim();
    card.querySelectorAll("button,input,textarea").forEach(function(x){x.disabled=true;});
    post("/api/answer",{id:id,verdict:v,note:note}).then(function(res){
      var vd=card.querySelector(".verdict"); vd.style.display="block";
      if(res.ok){var ok=v.indexOf("allow")===0;vd.className="verdict "+(ok?"a":"d");
        vd.textContent=(ok?"✓ ":"✗ ")+v.replace("-"," ").toUpperCase()+(note?" · noted":"");
        setTimeout(function(){loadGates();refreshHud();if(needsDrawerOpen())loadNext();},700);}
      else{vd.className="verdict d";vd.textContent=(res.j&&res.j.error)||"failed";
        card.querySelectorAll("button,input,textarea").forEach(function(x){x.disabled=false;});
        if(chk&&!chk.checked)allow.forEach(function(x){x.disabled=true;});}   // re-lock sensitive allow
    });
  });});
}
function needsDrawerOpen(){var d=document.getElementById("nextDrawer");return d&&d.style.display!=="none";}

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
    return {id:n.id,label:n.label,type:n.type,rank:n.rank,biz:n.business,code:n.code||"",reports:n.reports,
      source:n.source||"",learned:n.learned,caution:n.caution||"",   // carried so the node panel can show them
      x:(Math.random()-.5)*1.6,y:(Math.random()-.5)*1.6,z:(Math.random()-.5)*1.6,
      vx:0,vy:0,vz:0,r:n.type==="agent"?(n.rank==="Admiral"?16:n.rank==="Commander"?14:n.rank==="Captain"?10:6.5):(n.type==="file"?4.5:8),
      core:(n.label==="Rosco"||n.label==="Ross"),links:0,pulse:0,tw:Math.random()*6.28};});
  E=m.edges.map(function(e){return[byId[e.a],byId[e.b],e.kind];}).filter(function(e){return e[0]!=null&&e[1]!=null;});
  E.forEach(function(e){N[e[0]].links++;N[e[1]].links++;});
  layout(); if(N.length){ selected=byId["Rosco"]!=null?byId["Rosco"]:0; focusOn(selected);fx=tfx;fy=tfy;fz=tfz; resize(); }
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

var yaw=-.5,pitch=-.26,tYaw=yaw,tPitch=pitch,drag=false,lx=0,ly=0,downx=0,downy=0,auto=!reduce,hover=-1,selected=-1;
// Camera focus point: clicking a node flies IT to screen center (the graph orbits
// the selection instead of its own midpoint). tf* is the target, f* eases toward it.
var fx=0,fy=0,fz=0,tfx=0,tfy=0,tfz=0;
function focusOn(i){if(i>=0&&N[i]){tfx=N[i].x;tfy=N[i].y;tfz=N[i].z;}}
function rot(p){var X=p.x-fx,Y=p.y-fy,Z=p.z-fz,cy=Math.cos(yaw),sy=Math.sin(yaw),x=X*cy-Z*sy,z=X*sy+Z*cy,y=Y,cx=Math.cos(pitch),sx=Math.sin(pitch);
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
  if(auto&&!drag)tYaw+=.0015;yaw+=(tYaw-yaw)*.08;pitch+=(tPitch-pitch)*.08;fx+=(tfx-fx)*.08;fy+=(tfy-fy)*.08;fz+=(tfz-fz)*.08;ctx.clearRect(0,0,W,H);
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
    if(!dim&&(n.type==="agent"||n.r>=10||hi)){var big=n.r>=14;ctx.textAlign="center";
      if(n.code&&n.r>=10){ctx.font="700 9px ui-monospace,Consolas,monospace";ctx.fillStyle="#37b0a0";ctx.fillText(n.code,n.px,n.py-base-7-(big?13:11.5));}
      ctx.font="700 "+(big?12:n.r>=10?10.5:9.5)+"px ui-monospace,Consolas,monospace";ctx.fillStyle="#e8efeb";ctx.fillText(n.label,n.px,n.py-base-7);}
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
cv.addEventListener("mousedown",function(e){drag=true;auto=false;var b=cv.getBoundingClientRect();lx=e.clientX-b.left;ly=e.clientY-b.top;downx=lx;downy=ly;});
window.addEventListener("mouseup",function(){drag=false;});
cv.addEventListener("click",function(e){var b=cv.getBoundingClientRect(),mx=e.clientX-b.left,my=e.clientY-b.top;
  if(Math.hypot(mx-downx,my-downy)>5)return;   // released far from press = a rotate, not a click — don't hijack the camera
  var p=pick(mx,my);
  if(p>=0){selected=p;focusOn(p);N[p].pulse=1;showNode(N[p]);}});
cv.addEventListener("mouseleave",function(){tip.style.opacity=0;hover=-1;});

// ---- context panel: click a node -> its details; "back" -> the queue ----
function showNode(n){
  var ctx=document.getElementById("ctx");
  var col=(n.core?"#e8efeb":(TYPEC[n.type]||"#8aa"));
  var neigh=[]; E.forEach(function(e){ if(e[0]===byId[n.id])neigh.push(N[e[1]]); if(e[1]===byId[n.id])neigh.push(N[e[0]]); });
  var links=neigh.slice(0,12).map(function(m){ return "<span class='lchip' data-jump='"+esc(m.id)+"'>"+esc(m.label)+"</span>"; }).join(" ");
  ctx.innerHTML="<div class='back' id='back'>&larr; back to Needs you</div>"
    +"<div class='node-ctx'>"
    +"<div class='nm'>"+esc(n.label)+"</div>"
    +"<div class='rk' style='color:"+col+"'>"+esc(n.rank||n.type)+(n.code?" · "+esc(n.code):"")+"</div>"
    +(n.type==="file"?("<div class='kv'><div class='k'>Source</div><div class='v'>"+esc(n.source||"")+"</div></div>"
       +"<div class='kv'><div class='k'>Status</div><div class='v'>"+(n.learned?"learned into "+esc(n.biz||""):"queued — not learned yet")+"</div></div>"
       +"<div class='kv'><div class='k'>Detail</div><div class='v'>full copy cached locally — read without the internet</div></div>"):"")
    +(n.biz?"<div class='kv'><div class='k'>Business</div><div class='v'>"+esc(n.biz)+"</div></div>":"")
    +(n.type==="tool"&&n.caution?"<div class='kv'><div class='k'>Caution</div><div class='v' style='color:var(--amber)'>"+esc(n.caution)+"</div></div>":"")
    +(n.reports?"<div class='kv'><div class='k'>Reports to</div><div class='v'>"+esc(n.reports)+"</div></div>":"")
    +(links?"<div class='kv'><div class='k'>Linked</div><div class='v' style='display:flex;flex-wrap:wrap;gap:5px'>"+links+"</div></div>":"")
    +"</div>";
  document.getElementById("back").addEventListener("click",restoreQueue);
  ctx.querySelectorAll("[data-jump]").forEach(function(el){el.addEventListener("click",function(){
    var i=byId[el.getAttribute("data-jump")]; if(i!=null){selected=i;focusOn(i);N[i].pulse=1;showNode(N[i]);}});});
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
        if(r.j&&r.j.error){var e=document.createElement("div");e.className="n";e.textContent=r.j.error;mwrap.appendChild(e);}
      }
    }).catch(function(){mwrap.innerHTML="";var inp=document.createElement("input");inp.type="text";inp.placeholder="type a model id";mwrap.appendChild(inp);modelEl=inp;});
  }
  api("/api/cfg/state").then(function(r){
    var st=(r.ok&&r.j)||{};
    var provs=st.providers||["openrouter","anthropic","openai","gemini","xai","ollama"];
    provs.forEach(function(p){var o=document.createElement("option");o.value=p;o.textContent=p;provSel.appendChild(o);});
    var pin=(st.pins&&st.pins[n.id])||null;
    // What this agent uses RIGHT NOW: its pin if any, else its role default —
    // chat for Rosco (the Admiral), workhorse for the working agents. The dropdowns
    // preselect that, so they show the real current model, not the first in the list.
    var role=(n.id==="Rosco"||n.rank==="Admiral")?"chat":"workhorse";
    var eff=pin||((st.models&&st.models[role])||{});
    if(pin){curLine.className="amcur";
      curLine.innerHTML="Pinned to <b>"+esc(pin.model)+"</b> via "+esc(pin.provider)+" &middot; <span class='unpin'>unpin</span>";
      curLine.querySelector(".unpin").addEventListener("click",function(){
        post("/api/cfg/unpin",{agent:n.id}).then(function(r){ if(r.ok)showNode(n);
          else{res.className="res err";res.textContent=(r.j&&r.j.error)||"failed";}});});
    } else {curLine.className="amcur n";
      curLine.innerHTML="Using its "+esc(role)+" role default: <b>"+esc(eff.model||"?")+"</b> — not pinned.";}
    provSel.value=eff.provider||"openrouter";
    fillModels(eff.model||"");
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
    "<div class='rhead' id='rhead'>Needs you</div><div class='qwrap' id='qwrap'></div>";
  loadGates();
}

// ---- tools rail: each one shows its view in the right-panel context area ----
var ledgerAll=false;   // Ledger: false = only Rosco/agent actions, true = include your clicks
var TOOLS=[["Needs","M4 5h9M4 10h9M4 15h5M13 14l2.5 2.5L20 11"],
  ["Ledger","M6 3h12v18l-3-2-3 2-3-2-3 2zM9 8h6M9 12h5"],
  ["Track","M3 8l9-4 9 4v8l-9 4-9-4zM3 8l9 4 9-4M12 12v8"],
  ["People","M9 11a3 3 0 100-6 3 3 0 000 6zm7 8a7 7 0 00-14 0"],
  ["Tools","M14 7l3 3-8 8-3-3zM3 21l4-1"],["Spend","M4 18l5-6 4 4 7-9"],["Verify","M20 6L9 17l-5-5"]];
function card(title,sub){return "<div class='ask'><div class='top'><span class='who'>"+esc(title)+"</span></div>"+(sub?"<div class='said'>"+sub+"</div>":"")+"</div>";}
// Every rail item is a shelf that pops out (like Needs). There is no 'Queue' tool:
// the home pane IS the gates queue ('Needs you'), always visible — Needs opens its
// full drawer, and the ROSCO brand is the way back to the home view + the graph.
var SHELF={"People":["People · who's enrolled",renderPeople],
  "Tools":["Tools · connectors & repos",renderTools],
  "Spend":["Spend · model cost",renderSpend],
  "Verify":["Verify · chain integrity",renderVerify],
  "Track":["Track · shipments",renderTrack],
  "Ledger":["Ledger · what Rosco did",renderLedger]};
function showTool(name){
  if(name==="Needs"){openNext();return;}
  var sh=SHELF[name];if(sh){openShelf(sh[0],sh[1]);}
}
function focusMesh(){closeShelf();closeNext();selected=byId["Rosco"]!=null?byId["Rosco"]:selected;focusOn(selected);restoreQueue();
  var on=document.querySelector(".tool.on");if(on)on.classList.remove("on");}
function openShelf(title,render){var d=document.getElementById("shelfDrawer");if(!d)return;
  var t=document.getElementById("shelfTitle");if(t)t.textContent=title;
  var h=document.querySelector("header");if(h)d.style.top=Math.round(h.getBoundingClientRect().bottom)+"px";
  d.style.display="flex";requestAnimationFrame(function(){d.classList.add("open");});
  var body=document.getElementById("shelfBody");body.innerHTML="<div class='empty'>Loading…</div>";render(body);}
function closeShelf(){var d=document.getElementById("shelfDrawer");if(!d)return;
  d.classList.remove("open");setTimeout(function(){d.style.display="none";},200);
  var on=document.querySelector(".tool.on");if(on)on.classList.remove("on");}
function renderPeople(body){
  Promise.all([api("/api/people"),api("/api/grants")]).then(function(res){
    var ppl=(res[0].ok&&Array.isArray(res[0].j))?res[0].j:[], gr=(res[1].ok&&Array.isArray(res[1].j))?res[1].j:[];
    if(!ppl.length){body.innerHTML="<div class='empty'>No one enrolled yet.</div>";return;}
    body.innerHTML=ppl.map(function(p){
      var acc=gr.filter(function(g){return g.person===p.person&&g.allow;}).map(function(g){return g.business+":"+g.capability;});
      var ch=(p.handles||[]).map(function(h){return h.channel;}).join(", ");
      return card(p.person, esc(ch||"no channels")+(acc.length?"<br><span style='color:var(--dim)'>can reach: "+esc(acc.join(", "))+"</span>":""));
    }).join("");
  }).catch(function(){body.innerHTML="<div class='empty'>couldn't load people</div>";});}
function renderSpend(body){
  api("/api/spend").then(function(r){var d=(r.ok&&r.j)||{};
    body.innerHTML="<pre class='mono' style='white-space:pre-wrap;font-size:11.5px;color:var(--text);padding:2px 4px;margin:0'>"+esc(d.report||"(no spend yet)")+"</pre>"
      +"<div class='said' style='padding:0 4px;color:var(--dim)'>caps: "+esc((d.budgets||[]).map(function(b){return b.scope+" $"+b.cap;}).join(", ")||"none set")+"</div>";
  }).catch(function(){body.innerHTML="<div class='empty'>couldn't load spend</div>";});}
function renderVerify(body){
  api("/api/overview").then(function(r){var o=(r.ok&&r.j)||{};
    var col=o.chains==="sound"?"var(--green)":"var(--amber)";
    body.innerHTML=card("Chain integrity","<b style='color:"+col+"'>"+esc(o.chains||"?")+"</b> — every event's hash links to the prior")
      +card("Spend","$"+esc(o.spend!=null?o.spend.toFixed(2):"?")+" over "+esc(o.spendCalls||0)+" model calls")
      +card("Needs you",esc(o.waiting||0)+" gate(s) waiting");
  }).catch(function(){body.innerHTML="<div class='empty'>couldn't verify</div>";});}
function renderTools(body){
  api("/api/cfg/state").then(function(r){var d=(r.ok&&r.j)||{};
    var tools=d.tools||[], repos=d.repos||[];
    var html=tools.length?tools.map(function(t){return card(t.name,esc((t.businesses||[]).join(", ")||"*"));}).join(""):"<div class='empty'>No external tools registered.</div>";
    if(repos.length)html+="<div class='rhead' style='border-top:1px solid var(--line)'>Linked repos</div>"+repos.map(function(rp){return card(rp.slug||rp.repo||rp.business||JSON.stringify(rp),"");}).join("");
    body.innerHTML=html;
  }).catch(function(){body.innerHTML="<div class='empty'>couldn't load tools</div>";});}
function renderLedger(body){
  // Trust but verify — what Rosco and its agents DID, from the log. Defaults to
  // Rosco's own actions (your clicks hidden) so it reads as "what Rosco did".
  api("/api/ledger").then(function(r){var L=(r.ok&&Array.isArray(r.j&&r.j.ledger))?r.j.ledger:[];
    var ros=L.filter(function(x){return x.by!=="ross";});
    var view=ledgerAll?L:ros;
    body.innerHTML="";
    var tg=document.createElement("div");tg.className="lg-toggle";
    [[false,"What Rosco did",ros.length],[true,"Everything",L.length]].forEach(function(c){
      var b2=document.createElement("button");b2.className="ing-chip"+(ledgerAll===c[0]?" on":"");
      b2.textContent=c[1]+" · "+c[2];
      b2.addEventListener("click",function(){ledgerAll=c[0];renderLedger(body);});
      tg.appendChild(b2);});
    body.appendChild(tg);
    if(!view.length){var e=document.createElement("div");e.className="empty";
      e.textContent=ledgerAll?"Nothing logged yet.":"Rosco hasn't acted on its own yet — right now it proposes and you ship. As it earns trust, its actions land here.";
      body.appendChild(e);return;}
    view.forEach(function(x){var el=document.createElement("div");el.className="lg-row";
      var by=document.createElement("span");by.className="lg-by"+(x.by==="ross"?" you":"");by.textContent=x.by==="ross"?"you":x.by;
      var w=document.createElement("span");w.className="lg-what";w.textContent=x.what;
      var wn=document.createElement("span");wn.className="lg-when";wn.textContent=(x.at||"").slice(5,16).replace("T"," ");
      el.appendChild(by);el.appendChild(w);
      if(x.undo){var u=document.createElement("button");u.className="lg-undo";u.textContent="undo";
        u.addEventListener("click",function(){u.disabled=true;u.textContent="…";post("/api/ledger/undo",{undo:x.undo,id:x.id}).then(function(){renderLedger(body);});});el.appendChild(u);}
      el.appendChild(wn);body.appendChild(el);});
  }).catch(function(){body.innerHTML="<div class='empty'>couldn't load the ledger</div>";});}
function renderTrack(body){
  // From memory — Rosco captures the number + what's in the box as you PROCESS a
  // shipping email in Next. No live inbox scan.
  api("/api/tracking").then(function(r){
    var T=(r.ok&&Array.isArray(r.j&&r.j.tracking))?r.j.tracking:[];
    if(!T.length){body.innerHTML="<div class='empty'>No shipments yet. Rosco captures a tracking number — and what's in the box — whenever you process a shipping email in Next.</div>";return;}
    body.innerHTML="";
    T.forEach(function(x){var el=document.createElement("div");el.className="ask";
      var top=document.createElement("div");top.className="top";
      var who=document.createElement("span");who.className="who";who.textContent=x.item||x.carrier;
      var cap=document.createElement("span");cap.className="cap";
      var label=x.carrier+" "+x.number;
      if(x.url){var a=document.createElement("a");a.href=x.url;a.target="_blank";a.rel="noopener";a.textContent=label+" ↗";a.style.color="var(--steel)";cap.appendChild(a);}
      else cap.textContent=label;
      top.appendChild(who);top.appendChild(cap);el.appendChild(top);
      if(x.subject){var sd=document.createElement("div");sd.className="said";sd.textContent=x.subject;el.appendChild(sd);}
      var d=document.createElement("button");d.className="btn";d.textContent="Delivered ✓";
      d.addEventListener("click",function(){d.disabled=true;post("/api/tracking/close",{number:x.number}).then(function(){renderTrack(body);});});
      el.appendChild(d);body.appendChild(el);});
  }).catch(function(){body.innerHTML="<div class='empty'>couldn't load tracking</div>";});}
var tel=document.getElementById("tools");
TOOLS.forEach(function(t,i){var el=document.createElement("div");el.className="tool";
  el.innerHTML="<svg viewBox='0 0 24 24'><path d='"+t[1]+"'/></svg><span class='t'>"+t[0]+"</span>";
  el.addEventListener("click",function(){tel.querySelectorAll(".tool").forEach(function(x){x.classList.remove("on");});el.classList.add("on");showTool(t[0]);});
  tel.appendChild(el);});
// The ROSCO brand is the way back to the mesh (the graph is the canvas, not a rail item).
var brand=document.querySelector(".brand");
if(brand){brand.style.cursor="pointer";brand.title="Show the mesh";brand.addEventListener("click",focusMesh);}
var shc=document.getElementById("shelfClose");if(shc)shc.addEventListener("click",closeShelf);

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
// `voiceMsg` (a string) means this came from the mic — use it as the message and
// SPEAK the reply back. A typed message leaves both untouched.
function sendChat(voiceMsg){
  var inp=document.getElementById("chatin"),btn=document.getElementById("chatsend");
  var fromVoice=(typeof voiceMsg==="string");
  var msg=(fromVoice?voiceMsg:inp.value).trim(); if(!msg) return;
  bubble("you","Ross",msg); if(!fromVoice)inp.value=""; btn.disabled=true;
  var waiting=bubble("wait","Rosco","thinking…");
  post("/api/chat",{message:msg,ui:dashState()}).then(function(res){
    waiting.remove(); btn.disabled=false; if(!fromVoice)inp.focus();
    var reply=res.ok?(res.j.reply||"…"):((res.j&&res.j.error)||"couldn't reach the model.");
    bubble("ros","Rosco",reply);
    if(fromVoice) speak(reply);
  }).catch(function(){ waiting.remove(); btn.disabled=false;
    var e="server unreachable."; bubble("ros","Rosco",e); if(fromVoice)speak(e); });
}
document.getElementById("chatsend").addEventListener("click",sendChat);
// Starts readonly so Chrome's password manager won't pair it with the unlock
// passphrase field and offer to autofill a password into the chat box; drop that
// the moment it's focused so typing works normally.
document.getElementById("chatin").addEventListener("focus",function(){this.removeAttribute("readonly");});
document.getElementById("chatin").addEventListener("keydown",function(e){if(e.key==="Enter")sendChat();});

// ---- voice: full-listen mode ----------------------------------------------
// When on, the console listens continuously. Only an utterance that CONTAINS the
// wake word "rosco" is taken as an instruction (everything else is ignored, so
// ambient talk and the TV don't trigger it); the words after "rosco" are sent to
// the chat and the reply is spoken back. The browser can't verify WHO is speaking,
// so the wake word + your unlocked console (physical access) are the gate — true
// voice-fingerprinting would need a model. Zero dependencies: browser-native
// SpeechRecognition + SpeechSynthesis, both localhost-safe.
var wantListen=false, recog=null;
var WAKE=/\b(rosco|roscoe|rosko|rosca|ross[\s-]?go|russ[\s-]?co)\b/i;
function voiceSupported(){return !!(window.SpeechRecognition||window.webkitSpeechRecognition);}
function speak(text){
  if(!window.speechSynthesis) return;
  var t=(text||"").replace(/https?:\/\/\S+/g," (link) ")                 // don't read URLs aloud
    .replace(/[*_`#>]/g,"")                                              // markdown
    .replace(/[\u{1F000}-\u{1FAFF}\u{2600}-\u{27BF}\u{2190}-\u{21FF}\u{2B00}-\u{2BFF}\u{FE0F}]/gu,"")  // emoji/arrows
    .replace(/\s+/g," ").trim().slice(0,700);
  if(!t) return;
  try{window.speechSynthesis.cancel();var u=new SpeechSynthesisUtterance(t);u.rate=1.05;window.speechSynthesis.speak(u);}catch(e){}
}
function vhint(txt,acting){var h=document.getElementById("vhint");if(!h)return;
  h.textContent=txt||""; h.className="vhint"+(acting?" act":"");}
function handleUtterance(raw){
  // Ignore anything heard WHILE Rosco is speaking, so it never triggers on its own
  // voice (no feedback loop). Barge-in can come later.
  if(window.speechSynthesis&&window.speechSynthesis.speaking) return;
  var t=(raw||"").trim(); if(!t) return;
  var m=t.match(WAKE);
  if(!m){ vhint("· "+t.slice(0,64),false); return; }                     // not addressed to Rosco
  var instruction=t.slice(m.index+m[0].length).replace(/^[\s,.:!?-]+/,"").trim();
  if(!instruction){ vhint("▶ yes?",true); speak("Yes?"); return; }
  vhint("▶ "+instruction.slice(0,64),true);
  sendChat(instruction);
}
function setListenUI(on){var b=document.getElementById("micBtn");
  if(b){b.classList.toggle("on",on);b.title=on?"Listening — click to stop":"Voice: click to listen";}
  if(!on)vhint("",false);}
function startListen(){
  if(!voiceSupported()){alert("This browser can't do speech recognition — open the console in Chrome or Edge.");return;}
  wantListen=true;
  var SR=window.SpeechRecognition||window.webkitSpeechRecognition;
  try{recog=new SR();}catch(e){wantListen=false;return;}
  recog.continuous=true; recog.interimResults=false; recog.lang="en-US";
  recog.onresult=function(e){for(var i=e.resultIndex;i<e.results.length;i++){
    if(e.results[i].isFinal)handleUtterance(e.results[i][0].transcript);}};
  recog.onerror=function(e){ if(e.error==="not-allowed"||e.error==="service-not-allowed"){
    wantListen=false;setListenUI(false);alert("Rosco needs microphone permission to listen — allow it and click the mic again.");}};
  recog.onend=function(){ if(wantListen){try{recog.start();}catch(e){}} else setListenUI(false); };  // auto-restart = always-on
  try{recog.start();setListenUI(true);}catch(e){}
  try{localStorage.setItem("roscoListen","1");}catch(e){}
}
function stopListen(){wantListen=false;try{if(recog)recog.stop();}catch(e){}
  try{if(window.speechSynthesis)window.speechSynthesis.cancel();}catch(e){}
  setListenUI(false);try{localStorage.removeItem("roscoListen");}catch(e){}}
function toggleListen(){ wantListen?stopListen():startListen(); }
var _mic=document.getElementById("micBtn");
if(_mic)_mic.addEventListener("click",toggleListen);
// Re-arm on load if it was on last session — the origin already holds mic
// permission, so start() usually works without a fresh click. If the browser
// blocks it, the mic just shows off and one click resumes.
try{ if(localStorage.getItem("roscoListen")==="1"&&voiceSupported()) startListen(); }catch(e){}

// ---- settings: the CLI's config commands, as forms ----
var CFG=[
 {t:"Models",a:"model",n:"Pick a role, a provider, then a model your key can serve.",
  f:[{k:"role",l:"Role",sel:"roles"},{k:"provider",l:"Provider",sel:"providers"},{k:"model",l:"Model",dyn:"models"}]},
 {t:"API keys",a:"secret",n:"Stored encrypted in the vault. A live green check means the provider accepts it. Model keys and the GitHub token use scope 'system'; only Google's client id/secret go under each account. Click a row to fill its name.",
  f:[{k:"business",l:"Scope",sel:"scopes"},{k:"name",l:"Key name",ph:"openrouter_api_key"},{k:"value",l:"Value",type:"password"}]},
 {t:"Google Workspace",google:true,n:"Connect each Google account by OAuth — full Gmail/Drive/Calendar/Docs/Sheets/Chat/Contacts. Set that account's Client ID + secret on its row below, then Authorize and consent as the right account in the tab that opens.",f:[]},
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
// Each provider row shows, right under its key status, the live catalogue of
// models that key can serve — a browse-only list, so you can confirm the key
// works and see what's available. Assigning a model to a ROLE lives solely in the
// 'Models' section (one place, no duplicate control). openrouter/ollama list
// without a key; anthropic/openai/gemini/xai need a valid one, so a keyless
// provider shows none and its "not set" status stands as the answer.
function loadProviderModels(row,provider){
  api("/api/cfg/models?provider="+encodeURIComponent(provider)).then(function(r){
    var ids=(r.ok&&r.j&&r.j.models)||[];
    if(!ids.length) return;
    var sel=document.createElement("select");sel.className="ksmsel";
    var head=document.createElement("option");head.value="";
    head.textContent=ids.length+" model"+(ids.length===1?"":"s")+" your key can serve — assign a role in Models";
    sel.appendChild(head);
    ids.forEach(function(id){var o=document.createElement("option");o.value=id;o.textContent=id;sel.appendChild(o);});
    sel.addEventListener("click",function(e){e.stopPropagation();});   // browse only — don't trip the row's fill-key-name click
    row.appendChild(sel);
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
            if(r.j&&r.j.error){var e=document.createElement("div");e.className="n";e.textContent=r.j.error;wrap.appendChild(e);}
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
// Lock: end the session on demand (server drops the passphrase, chat + any pending
// write), then fall to the lock screen. The passphrase lives only in server memory,
// so this is the clean way to walk away without waiting for a restart.
document.getElementById("lockBtn").addEventListener("click",function(){
  post("/api/lock",{}).then(function(){relock("Locked. Unlock to continue.");})
    .catch(function(){relock("Locked. Unlock to continue.");});});

// ---- ingestion review: learn one item at a time ----
function ingestBusinesses(){return (cfgState&&cfgState.businesses)||[];}
function bizTitle(slug){return (cfgState&&cfgState.businessTitles&&cfgState.businessTitles[slug])||slug;}
var lastIngestBiz="";   // remember the last "File into" pick so bulk-routing (e.g. a whole repo into Rosco's Vault) is Enter, Enter, Enter
function setIngestPip(n){ingCount=n;var pip=document.getElementById("ingestPip");if(pip)pip.style.display=n>0?"inline-block":"none";}
function pollIngestPip(){api("/api/ingest/queue").then(function(r){setIngestPip(((r.ok&&r.j&&r.j.items)||[]).filter(function(x){return !isEmail(x);}).length);});}
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
  // or pull Google Drive contents — one file, or a whole batch (search / recent)
  var drow=document.createElement("div");drow.className="ing-row";
  var dl=document.createElement("label");dl.textContent="or Drive";drow.appendChild(dl);
  var dacc=document.createElement("input");dacc.type="text";dacc.value="personal";dacc.title="Google account";dacc.autocomplete="off";
  dacc.style.cssText="width:90px;background:var(--ground);border:1px solid var(--line-hot);color:var(--text);font:12.5px/1 var(--sans);padding:8px";
  var din=document.createElement("input");din.type="text";din.placeholder="search/folder, or blank = recent (pulls all matching)";din.autocomplete="off";
  din.style.cssText="flex:1;min-width:150px;background:var(--ground);border:1px solid var(--line-hot);color:var(--text);font:12.5px/1 var(--sans);padding:8px";
  var dbtn=document.createElement("button");dbtn.className="ing-go";dbtn.textContent="Pull from Drive";
  var dmsg=document.createElement("span");dmsg.className="ksst";
  dbtn.addEventListener("click",function(){var nm=din.value.trim(),acc=dacc.value.trim()||"personal";
    dbtn.disabled=true;dmsg.className="ksst";dmsg.textContent=nm?("searching "+acc+" Drive…"):("pulling recent from "+acc+" Drive…");
    post("/api/ingest/drive",{name:nm,account:acc,bulk:true}).then(function(r){dbtn.disabled=false;
      if(r.ok){din.value="";dmsg.className="ksst g";dmsg.textContent="queued "+r.j.added+" from "+(r.j.file||acc);loadIngest();}
      else{dmsg.className="ksst r";dmsg.textContent=(r.j&&r.j.error)||"couldn't pull";}});});
  drow.appendChild(dacc);drow.appendChild(din);drow.appendChild(dbtn);drow.appendChild(dmsg);host.appendChild(drow);
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
  // (Inbox triage moved to Next — the hopper is documents/knowledge only.)
  Promise.all([api("/api/ingest/queue"),api("/api/ingest/readiness")]).then(function(res){
    var q=(res[0].ok&&res[0].j&&res[0].j.items)||[];
    var rd=(res[1].ok&&res[1].j)||{};
    var docs=q.filter(function(x){return !isEmail(x);});   // the hopper is DOCS only — count what's actually reviewable
    setIngestPip(docs.length);
    host.appendChild(renderLadder(rd));            // the learning ladder — climbs as you approve
    if(rd.emailLessons>0){                          // Fix #2 cleanup: forget email notifications learned as facts
      var pw=document.createElement("div");pw.className="ing-prune";
      var pb=document.createElement("button");pb.className="em-btn warn";
      pb.textContent="Forget "+rd.emailLessons+" email-notification ‘facts’";
      var pm=document.createElement("span");pm.className="ksst";
      pb.addEventListener("click",function(){
        if(!confirm("Forget "+rd.emailLessons+" lessons learned from inbound email (promos, alerts, safe-access logs)? They were never durable facts. History stays on the log; the claims leave memory."))return;
        pb.disabled=true;pm.className="ksst";pm.textContent="forgetting…";
        post("/api/lessons/prune",{}).then(function(r){
          if(r.ok){pm.className="ksst g";pm.textContent="✓ forgot "+r.j.forgot;setTimeout(loadIngest,700);}
          else{pb.disabled=false;pm.className="ksst r";pm.textContent=(r.j&&r.j.error)||"failed";}
        }).catch(function(){pb.disabled=false;pm.className="ksst r";pm.textContent="unreachable";});});
      pw.appendChild(pb);pw.appendChild(pm);host.appendChild(pw);
    }
    if(docs.length){
      var nb=Math.min(rd.nextBatch||1,docs.length);
      var rb=document.createElement("div");rb.className="ing-ready";
      var msg=document.createElement("span");
      msg.textContent="Batch review — Rosco reads the next "+nb+", tells you how sure it is, you ✓/✗ each. Get them right and the batch grows (1→2→5→10→20); a wrong one snaps it back.";
      var ab=document.createElement("button");ab.className="ing-go";ab.textContent="Review next "+nb;
      ab.addEventListener("click",function(){ab.disabled=true;ab.textContent="reading "+nb+"…";openReportCard(host,nb);});
      rb.appendChild(msg);rb.appendChild(ab);host.appendChild(rb);
    }
    var bar=document.createElement("div");bar.className="ing-bar";
    var l=document.createElement("span");l.textContent=docs.length+" waiting";
    var rt=document.createElement("span");rt.textContent=(rd.decided||0)+" placed · "+Math.round((rd.rate||0)*100)+"% on target";
    bar.appendChild(l);bar.appendChild(rt);
    if(docs.length){var cl=document.createElement("button");cl.className="ing-clear";cl.textContent="Clear queue";
      cl.addEventListener("click",function(){
        if(!confirm("Skip all "+docs.length+" pending item(s)? They stay on the log as history but leave the queue, so you can re-ingest cleanly.")) return;
        cl.disabled=true;cl.textContent="clearing…";
        post("/api/ingest/clear",{}).then(function(r){ if(r.ok){loadIngest();}
          else{cl.disabled=false;cl.textContent="Clear queue";alert((r.j&&r.j.error)||"couldn't clear");} })
          .catch(function(){cl.disabled=false;cl.textContent="Clear queue";alert("server unreachable");});});
      bar.appendChild(cl);}
    host.appendChild(bar);
    if(!docs.length){var e=document.createElement("div");e.className="ing-empty";e.textContent="Nothing to review. Paste something above to begin.";host.appendChild(e);return;}
    host.appendChild(ingestCard(docs[0]));
  });
}
// ---- Next: the importance-ranked "what needs you" drawer, slid from the rail ----
var NXLABEL={reply:"Reply",archive:"Archive",keep:"Keep",done:"Done ✓",trash:"Trash",star:"Star",spam:"Spam"};
function nxLabel(a){return NXLABEL[a]||a;}
function openNext(){var d=document.getElementById("nextDrawer");if(!d)return;
  var h=document.querySelector("header");           // sit BELOW the main header, never over it
  if(h)d.style.top=Math.round(h.getBoundingClientRect().bottom)+"px";
  d.style.display="flex";requestAnimationFrame(function(){d.classList.add("open");});
  // The doc lane's "File into" needs cfgState.businesses; only the Ingest modal
  // loaded it before, so a cold session opening straight to Needs had an empty
  // dropdown and filing failed. Load it once here if missing, THEN render.
  if(cfgState&&cfgState.businesses){loadNext(true);}
  else{api("/api/cfg/state").then(function(r){if(r.ok&&r.j&&r.j.businesses)cfgState=r.j;loadNext(true);}).catch(function(){loadNext(true);});}}
function closeNext(){var d=document.getElementById("nextDrawer");if(!d)return;
  d.classList.remove("open");setTimeout(function(){d.style.display="none";},200);
  var on=document.querySelector(".tool.on");if(on)on.classList.remove("on");}
// The full "Needs you": the GATES band on top, then the typed lanes (email, docs,
// tasks, non-sensitive requests) — one /api/needs?full=1 fetch (Google + model),
// cached so re-focusing an email doesn't re-hit the inbox. Every card renderer and
// its post-action reload still call loadNext, so they keep working unchanged.
var lastNeeds=null, emailFocus=0;
function loadNext(force){var body=document.getElementById("nextBody");if(!body)return;
  // A background reload (after acting on any lane) must not rebuild the drawer
  // under a gate Ross is mid-decision on — his deny-why note would vanish. Skip
  // and let the gate's own resolve refresh. `force` (the initial open) bypasses.
  if(!force && cardBusy(body))return;
  body.innerHTML="<div class='ing-empty'>ranking what needs you…</div>";
  api("/api/needs?full=1").then(function(res){
    if(!res.ok||!res.j){body.innerHTML="<div class='ing-empty'>couldn't load</div>";return;}
    emailFocus=0; renderNeeds(res.j);
  }).catch(function(){body.innerHTML="<div class='ing-empty'>server unreachable</div>";});}
function laneHead(title,sub){var h=document.createElement("div");h.className="nx-lane";
  h.innerHTML="<span class='nx-lane-t'>"+esc(title)+"</span>"+(sub?"<span class='nx-lane-s'>"+esc(sub)+"</span>":"");return h;}
function renderNeeds(d){
  lastNeeds=d;
  var body=document.getElementById("nextBody");if(!body)return;
  body.innerHTML="";
  var band=d.band||[], lanes=d.lanes||{}, c=d.counts||{};
  setNeedsBadge(c.gates||0,c.work||0,!!c.sensitive);
  markWaiting(band.filter(function(b){return b.kind==="grant";}));
  // BAND — the gates
  if(band.length){
    body.appendChild(laneHead("⚠ Gates ("+band.length+")",
      c.sensitive?"someone's blocked — a SENSITIVE one is here":"someone is blocked on you"));
    renderBand(body,band);
  }
  // EMAIL — a scannable list with the top one expanded for full triage. It gets
  // its OWN container so re-focusing a row re-renders only this lane (no refetch,
  // and the band's in-progress deny-note / ack survive).
  var em=lanes.email||[];
  if(em.length){
    body.appendChild(laneHead("Email ("+em.length+")","most important first — who you reply to, not what a mail claims"));
    var elane=document.createElement("div");elane.className="nx-email-lane";body.appendChild(elane);
    renderEmailLane(elane,em);
  } else if(d.emailNote){
    body.appendChild(laneHead("Email",""));
    var nn=document.createElement("div");nn.className="ing-empty";nn.textContent=d.emailNote;body.appendChild(nn);
  }
  // DOCS — the hopper, quick file/skip; deep review stays in the Ingest modal
  var docs=lanes.doc||[];
  if(docs.length){
    var lad=(d.ladder&&d.ladder.stage)?("autonomy: "+d.ladder.stage):"";
    body.appendChild(laneHead("Docs to review ("+docs.length+")",lad));
    docs.slice(0,6).forEach(function(dc){body.appendChild(needsDocCard(dc));});
    if(docs.length>6){var mo=document.createElement("div");mo.className="nx-more";
      mo.textContent="+"+(docs.length-6)+" more — open Ingest to review in depth →";
      mo.addEventListener("click",openIngest);body.appendChild(mo);}
  }
  // TASKS
  var tks=lanes.task||[];
  if(tks.length){body.appendChild(laneHead("Tasks ("+tks.length+")",""));
    tks.forEach(function(tk){body.appendChild(taskCard(tk));});}
  // REQUESTS — Rosco's non-sensitive proactive suggestions (sensitive ones band above)
  var rqs=lanes.request||[];
  if(rqs.length){body.appendChild(laneHead("Rosco suggests ("+rqs.length+")",""));
    rqs.forEach(function(rq){body.appendChild(requestCard(rq));});}
  // Whole-surface empty → the verify digest (what Rosco did)
  if(!band.length&&!em.length&&!docs.length&&!tks.length&&!rqs.length){
    body.innerHTML="";body.appendChild(gatesEmpty(d.ledgerDigest||[]));}
}
// The email lane: the focused email is the full triage card; the rest are compact
// rows you can click to focus (re-render from cache — no re-hit of the inbox).
function renderEmailLane(host,em){
  if(emailFocus>=em.length)emailFocus=0;
  host.innerHTML="";
  host.appendChild(nextEmailCard(em[emailFocus], em.length-1));
  em.forEach(function(it,idx){ if(idx===emailFocus)return;
    var r=document.createElement("div");r.className="em-row";
    r.innerHTML="<span class='em-row-f'>"+esc((it.from||"").replace(/\s*<.*$/,""))+"</span>"
      +"<span class='em-row-s'>"+esc(it.subject||"(no subject)")+"</span>"
      +"<span class='em-row-c'>"+esc(nxLabel(it.suggest))+"</span>";
    r.addEventListener("click",function(){emailFocus=idx;renderEmailLane(host,em);});   // re-render THIS lane only
    host.appendChild(r);
  });
}
// A lean doc card for the drawer — quick File-into / Ingest / Skip, reloading the
// drawer (not the Ingest modal). Deep review + batch stay in the Ingest modal.
function needsDocCard(item){
  var card=document.createElement("div");card.className="ing-card";
  var txt=document.createElement("div");txt.className="ing-text";
  txt.textContent=(item.summary||item.text||"").slice(0,240);card.appendChild(txt);
  var row=document.createElement("div");row.className="ing-row";
  var lab=document.createElement("label");lab.textContent="File into";row.appendChild(lab);
  var sel=document.createElement("select");
  ingestBusinesses().forEach(function(bz){var o=document.createElement("option");o.value=bz;o.textContent=bizTitle(bz);if(bz===item.business)o.selected=true;sel.appendChild(o);});
  row.appendChild(sel);
  var go=document.createElement("button");go.className="ing-go";go.textContent="Ingest";
  go.addEventListener("click",function(){decideIngest(item.cand,sel.value,"ingest",card,item.summary||"",false,loadNext);});
  var skip=document.createElement("button");skip.className="ing-skip";skip.textContent="Skip";
  skip.addEventListener("click",function(){decideIngest(item.cand,"","skip",card,"",false,loadNext);});
  row.appendChild(go);row.appendChild(skip);card.appendChild(row);
  return card;
}
// A proactive request from Rosco — propose-only. Approve runs the safe/reversible
// act it named; Not now suppresses that type this session.
function requestCard(rq){
  var c=document.createElement("div");c.className="rq-card";
  var h=document.createElement("div");h.className="rq-title";h.textContent="Rosco suggests: "+(rq.title||"");
  var w=document.createElement("div");w.className="rq-why";w.textContent=rq.why||"";
  var acts=document.createElement("div");acts.className="rq-acts";
  var msg=document.createElement("span");msg.className="ksst";
  var yes=document.createElement("button");yes.className="em-btn primary";yes.textContent="Approve";
  var no=document.createElement("button");no.className="em-btn";no.textContent="Not now";
  yes.addEventListener("click",function(){
    c.querySelectorAll("button").forEach(function(b){b.disabled=true;});msg.className="ksst";msg.textContent="working…";
    post("/api/requests",{id:rq.id,business:rq.business,cands:rq.cands}).then(function(r){
      if(r.ok){msg.className="ksst g";
        msg.textContent="✓ "+(r.j.filed!=null?("filed "+r.j.filed+" into "+(r.j.business||"")):(r.j.forgot!=null?("forgot "+r.j.forgot):"done"));
        setTimeout(loadNext,850);}
      else{c.querySelectorAll("button").forEach(function(b){b.disabled=false;});msg.className="ksst r";msg.textContent=(r.j&&r.j.error)||"failed";}
    }).catch(function(){c.querySelectorAll("button").forEach(function(b){b.disabled=false;});msg.className="ksst r";msg.textContent="unreachable";});});
  no.addEventListener("click",function(){yes.disabled=true;no.disabled=true;post("/api/requests",{id:rq.id,decline:true}).then(function(){loadNext();});});
  acts.appendChild(yes);acts.appendChild(no);
  c.appendChild(h);c.appendChild(w);
  // See exactly what will happen before approving — the items + where each goes.
  if(rq.preview&&rq.preview.length){
    var verb=rq.verb||"do";
    var lab=function(open){return (open?"▾":"▸")+" Review "+rq.preview.length+(rq.more?("+"+rq.more):"")+" to "+verb;};
    var tg=document.createElement("button");tg.className="rq-toggle";tg.textContent=lab(false);
    var lst=document.createElement("div");lst.className="rq-preview";lst.style.display="none";
    rq.preview.forEach(function(p){var pr=document.createElement("div");pr.className="rq-pv";
      var b=document.createElement("span");b.className="rq-pv-b";b.textContent=bizTitle(p.business||"");
      var tx=document.createElement("span");tx.className="rq-pv-t";tx.textContent=p.text||"";
      pr.appendChild(b);pr.appendChild(tx);lst.appendChild(pr);});
    if(rq.more){var mo=document.createElement("div");mo.className="rq-pv rq-more";mo.textContent="+ "+rq.more+" more";lst.appendChild(mo);}
    tg.addEventListener("click",function(){var open=lst.style.display==="none";lst.style.display=open?"block":"none";tg.textContent=lab(open);});
    c.appendChild(tg);c.appendChild(lst);
  }
  c.appendChild(acts);c.appendChild(msg);return c;
}
function taskCard(tk){
  var c=document.createElement("div");c.className="tk-card";
  var main=document.createElement("div");main.className="tk-main";
  var t=document.createElement("div");t.className="tk-text";t.textContent=tk.text||"";main.appendChild(t);
  if(tk.from||tk.subject){var m=document.createElement("div");m.className="tk-meta";
    m.textContent=(tk.from?("from "+tk.from):"")+(tk.subject?("  ·  "+tk.subject):"");main.appendChild(m);}
  var d=document.createElement("button");d.className="em-btn done";d.textContent="Done ✓";
  d.addEventListener("click",function(){d.disabled=true;post("/api/task/done",{id:tk.id}).then(function(){loadNext();});});
  c.appendChild(main);c.appendChild(d);return c;
}
// Split the badge: GATES is the primary count (turns red when a sensitive gate is
// present) — the only number that should ever nag. WORK (email/docs/tasks) is a
// muted sub-count, so a promo landing never inflates the alarming number.
function setNeedsBadge(gates,work,sensitive){var tools=document.querySelectorAll(".tool");
  for(var i=0;i<tools.length;i++){var t=tools[i].querySelector(".t");
    if(t&&t.textContent==="Needs"){
      var b=tools[i].querySelector(".badge");
      if(gates>0){if(!b){b=document.createElement("span");b.className="badge";tools[i].appendChild(b);}
        b.textContent=gates;if(sensitive)b.classList.add("sens");else b.classList.remove("sens");}
      else if(b){b.remove();}
      var w=tools[i].querySelector(".badge-work");
      if(work>0){if(!w){w=document.createElement("span");w.className="badge-work";tools[i].appendChild(w);}w.textContent=work;}
      else if(w){w.remove();}
      break;}}}
function cap(s){return s?s.charAt(0).toUpperCase()+s.slice(1):s;}
// One inbound email at a time, top of the importance pile, full triage verbs.
// After a "clear it" verb Rosco sweeps the rest of that sender's domain so you
// clear the lookalikes in one click — the fast path through a repetitive inbox.
function nextEmailCard(item,moreCount){
  var card=document.createElement("div");card.className="ing-card email";
  var imp=document.createElement("div");imp.className="nx-why";
  imp.textContent="▲ "+(item.why||"recent inbox mail")+(moreCount>0?("     ·  "+moreCount+" more after this"):"");
  card.appendChild(imp);
  var hd=document.createElement("div");hd.className="em-head";
  var f=document.createElement("span");f.className="em-from";f.textContent=item.from||"(unknown sender)";
  var sj=document.createElement("span");sj.className="em-subj";sj.textContent=item.subject||"(no subject)";
  hd.appendChild(f);hd.appendChild(sj);card.appendChild(hd);
  if(item.snippet){var tx=document.createElement("div");tx.className="ing-text";tx.textContent=item.snippet;card.appendChild(tx);}
  var sug=document.createElement("div");sug.className="nx-sug";
  var sb=document.createElement("b");sb.textContent="Rosco: "+nxLabel(item.suggest);
  var sw=document.createElement("span");sw.textContent=" — "+(item.suggestWhy||"");
  sug.appendChild(sb);sug.appendChild(sw);card.appendChild(sug);
  var msg=document.createElement("span");msg.className="ksst";
  var row=document.createElement("div");row.className="em-acts";
  function btn(label,action,cls){var b=document.createElement("button");
    b.className="em-btn"+(cls?" "+cls:"")+(action===item.suggest?" primary":"");b.textContent=label;
    b.addEventListener("click",function(){oneEmailAct(item,action,card,msg);});return b;}
  row.appendChild(btn("Done ✓","done","done"));
  row.appendChild(btn("Archive","archive"));
  row.appendChild(btn("Star","star"));
  row.appendChild(btn("Keep","keep"));
  row.appendChild(btn("Trash","trash","warn"));
  row.appendChild(btn("Spam","spam","warn"));
  var replyBtn=document.createElement("button");replyBtn.className="em-btn";replyBtn.textContent="Reply → draft";
  row.appendChild(replyBtn);
  var taskBtn=document.createElement("button");taskBtn.className="em-btn done";taskBtn.textContent="→ Task";
  row.appendChild(taskBtn);
  card.appendChild(row);card.appendChild(msg);
  var comp=document.createElement("div");comp.className="em-compose";comp.style.display="none";
  var ta=document.createElement("textarea");ta.placeholder="Write the reply — saves an unsent Gmail draft you send.";
  var crow=document.createElement("div");crow.className="em-crow";
  var save=document.createElement("button");save.className="ing-go";save.textContent="Save draft";
  var cancel=document.createElement("button");cancel.className="ing-skip";cancel.textContent="Cancel";
  crow.appendChild(save);crow.appendChild(cancel);comp.appendChild(ta);comp.appendChild(crow);card.appendChild(comp);
  replyBtn.addEventListener("click",function(){var open=comp.style.display==="none";comp.style.display=open?"block":"none";if(open)ta.focus();});
  cancel.addEventListener("click",function(){comp.style.display="none";});
  save.addEventListener("click",function(){var t=ta.value.trim();if(!t){ta.focus();return;}oneEmailAct(item,"reply",card,msg,t);});
  // "→ Task": for an important one you're closing out — capture the follow-up AND archive it in one move.
  var tcomp=document.createElement("div");tcomp.className="em-compose";tcomp.style.display="none";
  var tin=document.createElement("input");tin.type="text";tin.className="task-in";tin.autocomplete="off";
  tin.placeholder="What's the follow-up?";tin.value=item.subject||"";
  var tc=document.createElement("div");tc.className="em-crow";
  var tsave=document.createElement("button");tsave.className="ing-go";tsave.textContent="Make task + archive";
  var tcancel=document.createElement("button");tcancel.className="ing-skip";tcancel.textContent="Cancel";
  tc.appendChild(tsave);tc.appendChild(tcancel);tcomp.appendChild(tin);tcomp.appendChild(tc);card.appendChild(tcomp);
  // On open, have Rosco READ the email and pre-fill a brief, specific to-do — so
  // the task reads as an action, not just the subject line. Distilled once; Ross
  // sees it and can tweak before saving. Falls back to the subject on any hiccup.
  var suggested=false;
  taskBtn.addEventListener("click",function(){
    var open=tcomp.style.display==="none";tcomp.style.display=open?"block":"none";
    if(!open)return;
    tin.focus();tin.select();
    if(suggested||!(item.ref&&item.ref.id))return;
    suggested=true;
    var fallback=tin.value||item.subject||"";
    tin.value="";tin.disabled=true;tin.placeholder="Rosco is reading the email…";
    post("/api/task/suggest",{ref:item.ref}).then(function(r){
      tin.disabled=false;tin.placeholder="What's the follow-up?";
      tin.value=(r.ok&&r.j&&r.j.text)?r.j.text:fallback;tin.focus();tin.select();
    }).catch(function(){tin.disabled=false;tin.placeholder="What's the follow-up?";tin.value=fallback;});
  });
  tcancel.addEventListener("click",function(){tcomp.style.display="none";});
  tsave.addEventListener("click",function(){var t=tin.value.trim();if(!t){tin.focus();return;}
    card.querySelectorAll("button,textarea,input").forEach(function(b){b.disabled=true;});msg.className="ksst";msg.textContent="making task…";
    post("/api/task",{ref:item.ref,text:t}).then(function(r){
      if(r.ok){msg.className="ksst g";msg.textContent="✓ task made"+(r.j.gtask?" · in Google Tasks":"")+(r.j.archived?" + archived":"");setTimeout(loadNext,700);}
      else{card.querySelectorAll("button,textarea,input").forEach(function(b){b.disabled=false;});msg.className="ksst r";msg.textContent=(r.j&&r.j.error)||"failed";}
    }).catch(function(){card.querySelectorAll("button,textarea,input").forEach(function(b){b.disabled=false;});msg.className="ksst r";msg.textContent="unreachable";});});
  // Talk it through with Rosco — grounded in THIS email. A read: it explains or
  // drafts, never sends. Handy when you're not sure what an email even wants.
  var chat=document.createElement("div");chat.className="nx-chat";
  var thread=document.createElement("div");thread.className="nx-chat-thread";
  var crow2=document.createElement("div");crow2.className="nx-chat-row";
  var cin2=document.createElement("input");cin2.type="text";cin2.className="nx-chat-in";cin2.autocomplete="off";
  cin2.placeholder="Talk to Rosco about this email…";
  var cbtn=document.createElement("button");cbtn.className="em-btn";cbtn.textContent="Ask";
  crow2.appendChild(cin2);crow2.appendChild(cbtn);chat.appendChild(thread);chat.appendChild(crow2);card.appendChild(chat);
  function bub(cls,who,text){var m=document.createElement("div");m.className="nx-cb "+cls;
    var by=document.createElement("span");by.className="nx-cb-by";by.textContent=who;
    var d=document.createElement("span");d.className="nx-cb-t";d.textContent=text;
    m.appendChild(by);m.appendChild(d);thread.appendChild(m);thread.scrollTop=thread.scrollHeight;return d;}
  function ask(){var q=cin2.value.trim();if(!q)return;cin2.value="";bub("you","You",q);
    var w=bub("ros","Rosco","thinking…");cbtn.disabled=true;
    post("/api/email/chat",{ref:item.ref,message:q}).then(function(r){cbtn.disabled=false;
      w.textContent=(r.ok&&r.j&&r.j.reply)||"(couldn't answer)";cin2.focus();})
      .catch(function(){cbtn.disabled=false;w.textContent="(server unreachable)";});}
  cbtn.addEventListener("click",ask);cin2.addEventListener("keydown",function(e){if(e.key==="Enter")ask();});
  return card;
}
function oneEmailAct(item,action,card,msg,text){
  card.querySelectorAll("button,textarea").forEach(function(b){b.disabled=true;});
  msg.className="ksst";msg.textContent="working…";
  var b={ref:item.ref,action:action};if(text)b.text=text;
  post("/api/ingest/gmail",b).then(function(r){
    if(r.ok){
      if(r.j.similar&&r.j.similar.count>0){showSweep(card,msg,r.j.similar);}
      else{msg.className="ksst g";msg.textContent="✓ "+(r.j.msg||action);setTimeout(loadNext,500);}
    }else{card.querySelectorAll("button,textarea").forEach(function(x){x.disabled=false;});msg.className="ksst r";msg.textContent=(r.j&&r.j.error)||"couldn't do that";}
  }).catch(function(){card.querySelectorAll("button,textarea").forEach(function(x){x.disabled=false;});msg.className="ksst r";msg.textContent="server unreachable";});
}
// The sweep: "you archived this — N more from the same domain; clear them all?"
function showSweep(card,msg,sim){
  msg.className="ksst g";msg.textContent="✓ "+sim.action+"d";
  var box=document.createElement("div");box.className="nx-sweep";
  var t=document.createElement("div");t.className="nx-sweep-t";
  t.textContent="Found "+sim.count+" more from "+sim.domain+". "+cap(sim.action)+" all "+sim.count+" too?";
  var acts=document.createElement("div");acts.className="em-acts";
  var m2=document.createElement("span");m2.className="ksst";
  var yes=document.createElement("button");yes.className="em-btn primary";yes.textContent=cap(sim.action)+" all "+sim.count;
  var no=document.createElement("button");no.className="em-btn";no.textContent="Just this one";
  yes.addEventListener("click",function(){yes.disabled=true;no.disabled=true;m2.className="ksst";m2.textContent="sweeping…";
    post("/api/gmail/batch",{action:sim.action,refs:sim.refs}).then(function(r){
      if(r.ok){m2.className="ksst g";m2.textContent="✓ "+sim.action+"d "+((r.j.done||0)+1)+" from "+sim.domain;setTimeout(loadNext,750);}
      else{yes.disabled=false;no.disabled=false;m2.className="ksst r";m2.textContent=(r.j&&r.j.error)||"failed";}
    }).catch(function(){yes.disabled=false;no.disabled=false;m2.className="ksst r";m2.textContent="unreachable";});});
  no.addEventListener("click",function(){yes.disabled=true;no.disabled=true;setTimeout(loadNext,150);});
  acts.appendChild(yes);acts.appendChild(no);
  box.appendChild(t);box.appendChild(acts);box.appendChild(m2);card.appendChild(box);
}
// The autonomy ladder — learning → crawling → walking → running → auto. Rungs
// light up to the current stage; the caption says what earns the next one. It
// climbs live: every accepted placement in the report card refreshes this.
function renderLadder(rd){
  var stages=(rd&&rd.stages)||["learning","crawling","walking","running","auto"];
  var idx=(rd&&typeof rd.stageIndex==="number")?rd.stageIndex:0;
  var wrap=document.createElement("div");wrap.className="ladder";
  var head=document.createElement("div");head.className="ladder-head";
  var ll=document.createElement("span");ll.className="ll";
  ll.innerHTML="Rosco is <b>"+esc(stages[idx]||"learning")+"</b>";
  var ln=document.createElement("span");ln.className="ln";ln.textContent=(rd&&rd.toNext)||"";
  head.appendChild(ll);head.appendChild(ln);wrap.appendChild(head);
  var track=document.createElement("div");track.className="ladder-track";
  stages.forEach(function(s,i){
    var seg=document.createElement("div");seg.className="lseg"+(i<=idx?" on":"")+(i===idx?" cur":"");
    seg.title=s;
    var dot=document.createElement("span");dot.className="lsdot";
    var nm=document.createElement("span");nm.className="lsname";nm.textContent=s;
    seg.appendChild(dot);seg.appendChild(nm);track.appendChild(seg);
  });
  wrap.appendChild(track);
  if(rd&&(rd.streak||rd.decided)){
    var s=document.createElement("div");s.className="ladder-sub";
    s.textContent="streak "+(rd.streak||0)+" · "+(rd.decided||0)+" placed · "+Math.round((rd.rate||0)*100)+"% on target";
    wrap.appendChild(s);
  }
  return wrap;
}
function isEmail(x){return !!x&&(x.kind==="email"||((x.source||"").indexOf("gmail:")===0));}
function ingestCard(item){
  var card=document.createElement("div");card.className="ing-card";
  var shorthand=item.summary||"";   // the distilled form that actually gets learned (not the raw text)
  var touched=false;                // did Ross pick a business himself? then don't auto-move it
  // Lead with the shorthand — what actually gets learned — since judging IT (and
  // the business) is the decision. The raw source is secondary, collapsed below,
  // so it never buries the thing you're deciding on.
  var rd=document.createElement("div");rd.className="ing-reads";
  rd.innerHTML="<span class='rl'>Rosco's shorthand · this is what gets learned</span> <span class='rv'>"+(item.summary?esc(item.summary):"distilling…")+"</span>";
  card.appendChild(rd);
  var prop=document.createElement("div");prop.className="ing-prop";
  function showProp(biz,conf,why){prop.innerHTML="";
    if(biz){var s1=document.createElement("span");s1.textContent="Rosco →";
      var b=document.createElement("b");b.textContent=bizTitle(biz);
      var s2=document.createElement("span");s2.textContent=Math.round((conf||0)*100)+"% · "+(why||"");
      prop.appendChild(s1);prop.appendChild(b);prop.appendChild(s2);}
    else{var s0=document.createElement("span");s0.textContent=(item.summary?"Rosco isn't sure — you place this one":"reading…");prop.appendChild(s0);}}
  showProp(item.business,item.confidence,item.why);
  card.appendChild(prop);
  // The raw source — collapsed by default so it never buries the shorthand. When
  // opened it's a single contained scroll box (no more double-scrollbar).
  var src=document.createElement("details");src.className="ing-src";
  var sm=document.createElement("summary");sm.textContent="Original source · "+(item.text||"").length.toLocaleString()+" chars";
  var txt=document.createElement("div");txt.className="ing-text";txt.textContent=item.text||"";
  src.appendChild(sm);src.appendChild(txt);card.appendChild(src);
  var row=document.createElement("div");row.className="ing-row";
  var lab=document.createElement("label");lab.textContent="File into";row.appendChild(lab);
  var sel=document.createElement("select");
  var ingDef=item.business||lastIngestBiz;   // Rosco's stored pick first, else the last one used
  ingestBusinesses().forEach(function(bz){var o=document.createElement("option");o.value=bz;o.textContent=bizTitle(bz);if(bz===ingDef)o.selected=true;sel.appendChild(o);});
  sel.addEventListener("change",function(){touched=true;});
  row.appendChild(sel);
  // On-demand read: distill the shorthand AND swing "File into" to Rosco's fresh
  // read of THIS item (unless Ross already picked one himself).
  if(!item.summary){post("/api/ingest/read",{text:item.text}).then(function(r){
    var v=rd.querySelector(".rv");
    if(r.ok&&r.j&&r.j.summary){shorthand=r.j.summary;if(v)v.textContent=r.j.summary;
      if(r.j.business&&!touched){
        if(Array.prototype.some.call(sel.options,function(o){return o.value===r.j.business;}))sel.value=r.j.business;
        showProp(r.j.business,r.j.confidence,r.j.why);
      }
    } else if(v){v.textContent="(couldn't read — "+((r.j&&(r.j.why||r.j.error))||"no reason given")+")";}
  }).catch(function(){var v=rd.querySelector(".rv");if(v)v.textContent="(couldn't read — server unreachable)";});}
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
function decideIngest(cand,business,action,card,shorthand,emailFact,reload){
  // Guard the silent loop: 'ingest' with no business raises 'unknown business' on
  // the server, which never records the decision — so the item comes back forever.
  // Refuse here with a clear nudge instead. (Skip needs no business.)
  if(action==="ingest" && !((business||"").trim())){
    var gs=card&&card.querySelector("select");
    if(gs&&!gs.options.length)alert("No businesses to file into yet — add them in Settings, or hit Skip.");
    else{alert("Pick a business in 'File into' to file this, or hit Skip.");if(gs)gs.focus();}
    return;
  }
  if(card)card.querySelectorAll("button,select").forEach(function(x){x.disabled=true;});
  post("/api/ingest/decide",{cand:cand,business:business,action:action,shorthand:shorthand||"",emailFact:!!emailFact}).then(function(r){
    if(r.ok){(reload||loadIngest)();}
    else{alert((r.j&&r.j.error)||"couldn't decide");if(card)card.querySelectorAll("button,select").forEach(function(x){x.disabled=false;});}
  }).catch(function(){alert("server unreachable");if(card)card.querySelectorAll("button,select").forEach(function(x){x.disabled=false;});});
}
// Batch review — a report card. Rosco reads the next N in one pass, shows where
// each goes + how sure; you ✓ (right) or ✗ (wrong → pick the real home / skip),
// then place all. Nothing is learned until you approve; a ✗ correction is the
// honest signal that snaps the trust ladder back.
function openReportCard(host,n){
  post("/api/ingest/autopreview",{n:n}).then(function(r){
    if(!(r.ok&&r.j)){alert((r.j&&r.j.error)||"couldn't read the batch");loadIngest();return;}
    renderReportCard(host,r.j.items||[],r.j.confidence||0);
  }).catch(function(){alert("server unreachable");loadIngest();});
}
function renderReportCard(host,items,confidence){
  host.innerHTML="";
  if(!items.length){host.innerHTML="<div class='ing-empty'>Nothing to review.</div>";return;}
  var head=document.createElement("div");head.className="rc-head";
  head.innerHTML="I read the next <b>"+items.length+"</b> — about <b>"+confidence+"%</b> confident where they go. Green ✓ if I'm right, red ✗ if I'm wrong (then pick the real home, or skip). That correction is how I learn.";
  host.appendChild(head);
  var tbl=document.createElement("div");tbl.className="rc-tbl";
  var th=document.createElement("div");th.className="rc-tr rc-th";
  th.innerHTML="<div>Shorthand</div><div>Why it's going where</div><div>OK?</div>";
  tbl.appendChild(th);
  var rows=[];
  items.forEach(function(it){
    var st={cand:it.cand,shorthand:it.summary,business:it.business,proposed:it.business};rows.push(st);
    var tr=document.createElement("div");tr.className="rc-tr ok";
    // col 1 — shorthand (with a small filename tag)
    var c1=document.createElement("div");c1.className="rc-c1";
    var nm=document.createElement("span");nm.className="rc-name";nm.textContent=(it.name||"").split("/").pop()||"item";
    var gist=document.createElement("div");gist.className="rc-gist";gist.textContent=it.summary||"(no shorthand)";
    c1.appendChild(nm);c1.appendChild(gist);
    // col 2 — why it's going where (turns into a picker on ✗)
    var c2=document.createElement("div");c2.className="rc-c2";
    var why=document.createElement("div");why.className="rc-why";
    why.innerHTML="→ <b>"+esc(bizTitle(it.business)||"unplaced")+"</b><br>"+esc(it.why||"")+" · "+it.confidence+"%";
    var fix=document.createElement("select");fix.className="karole rc-fix";fix.style.display="none";
    var sk=document.createElement("option");sk.value="";sk.textContent="— skip —";fix.appendChild(sk);
    // NOTE: do NOT pre-select it.business — on ✗ the picker must default to
    // "— skip —" so an untouched "wrong" skips rather than silently re-filing
    // into the very business Ross just rejected (which also mis-scored the ladder).
    ingestBusinesses().forEach(function(bz){var o=document.createElement("option");o.value=bz;o.textContent=bizTitle(bz);fix.appendChild(o);});
    fix.addEventListener("change",function(){st.business=fix.value;});
    c2.appendChild(why);c2.appendChild(fix);
    // col 3 — ✓ / ✗
    var c3=document.createElement("div");c3.className="rc-c3";
    var yes=document.createElement("button");yes.className="rc-yes on";yes.textContent="✓";yes.title="right";
    var no=document.createElement("button");no.className="rc-no";no.textContent="✗";no.title="wrong — pick the real home";
    yes.addEventListener("click",function(){st.business=it.business;fix.style.display="none";why.style.display="";tr.className="rc-tr ok";yes.className="rc-yes on";no.className="rc-no";});
    no.addEventListener("click",function(){st.business=fix.value;fix.style.display="";why.style.display="none";tr.className="rc-tr wrong";no.className="rc-no on";yes.className="rc-yes";});
    c3.appendChild(yes);c3.appendChild(no);
    tr.appendChild(c1);tr.appendChild(c2);tr.appendChild(c3);tbl.appendChild(tr);
  });
  host.appendChild(tbl);
  var foot=document.createElement("div");foot.className="rc-foot";
  var place=document.createElement("button");place.className="ing-go";place.textContent="Place all "+items.length;
  place.addEventListener("click",function(){place.disabled=true;place.textContent="placing…";
    post("/api/ingest/autoplace",{items:rows.map(function(st){return {cand:st.cand,business:st.business,shorthand:st.shorthand,proposed:st.proposed};})})
      .then(function(){loadIngest();}).catch(function(){place.disabled=false;place.textContent="Place all";alert("server unreachable");});});
  var back=document.createElement("button");back.className="ing-skip";back.textContent="Cancel";
  back.addEventListener("click",loadIngest);
  foot.appendChild(place);foot.appendChild(back);host.appendChild(foot);
}
document.getElementById("ingestBtn").addEventListener("click",openIngest);
document.getElementById("ingestClose").addEventListener("click",closeIngest);
var nc=document.getElementById("nextClose");if(nc)nc.addEventListener("click",closeNext);

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
