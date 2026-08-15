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
function boot(){ refreshHud(); loadQueue(); loadMesh(); setInterval(refreshHud,8000); }

function refreshHud(){ api("/api/overview").then(function(res){var o=res.j;if(!o)return;
  document.getElementById("hud").innerHTML=
    stat("Waiting","<span class='dot "+(o.waiting?"a":"g")+"'></span>"+o.waiting)+
    stat("Spend","$"+o.spend.toFixed(2))+
    stat("Chains","<span class='dot "+(o.chains==="sound"?"g":"a")+"'></span>"+o.chains);
});}
function stat(k,v){return "<div class='stat'><span class='k'>"+k+"</span><span class='v'>"+v+"</span></div>";}

// ---- the queue ----
var SENS={"bound-book":1,"books":1,"payroll":1,"taxes":1,"transfers":1,"budget":1};
function loadQueue(){ api("/api/queue").then(function(res){var q=res.j||[];var el=document.getElementById("qwrap");
  document.getElementById("rhead").textContent="Waiting on you · "+q.length;
  if(!q.length){el.innerHTML="<div class='empty'>Nothing waiting. You're clear.</div>";return;}
  el.innerHTML=q.map(askCard).join("");
  q.forEach(function(a){ wireCard(a.id); });
});}
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

function loadMesh(){ api("/api/mesh").then(function(res){var m=res.j||{nodes:[],edges:[]};
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
cv.addEventListener("click",function(e){var b=cv.getBoundingClientRect(),p=pick(e.clientX-b.left,e.clientY-b.top);if(p>=0){selected=p;N[p].pulse=1;}});
cv.addEventListener("mouseleave",function(){tip.style.opacity=0;hover=-1;});

// ---- tools rail (navigation stubs for now) ----
var TOOLS=[["Mesh","M12 3v4M12 17v4M3 12h4M17 12h4M12 8a4 4 0 100 8 4 4 0 000-8z"],
  ["Queue","M4 6h16M4 12h16M4 18h10"],["People","M9 11a3 3 0 100-6 3 3 0 000 6zm7 8a7 7 0 00-14 0"],
  ["Tools","M14 7l3 3-8 8-3-3zM3 21l4-1"],["Spend","M4 18l5-6 4 4 7-9"],["Verify","M20 6L9 17l-5-5"]];
var tel=document.getElementById("tools");
TOOLS.forEach(function(t,i){var el=document.createElement("div");el.className="tool"+(i===0?" on":"");
  el.innerHTML="<svg viewBox='0 0 24 24'><path d='"+t[1]+"'/></svg><span class='t'>"+t[0]+"</span>";
  el.addEventListener("click",function(){tel.querySelectorAll(".tool").forEach(function(x){x.classList.remove("on");});el.classList.add("on");});
  tel.appendChild(el);});

resize();if(!reduce)setInterval(fire,850);requestAnimationFrame(frame);
