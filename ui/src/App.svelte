<script lang="ts">
  import { onMount } from 'svelte';
  import { openUrl } from '@tauri-apps/plugin-opener';
  import UpdateDialog from './lib/UpdateDialog.svelte';

  // The desktop WebView origin is a Tauri-owned asset origin, not bmc-provisionerd.
  // Both the packaged desktop app and Vite development UI therefore use the local API
  // service explicitly.  Using window.location.origin here makes a packaged build fetch
  // its own HTML fallback and later try to iterate an object as the BMC candidate list.
  const base = 'http://127.0.0.1:6770';
  type Candidate = { scopeId:number; scopeName:string; subnet:string; prefix:number; ip:string; mac?:string; source:'confirmedDiscovery'|'relayDhcpLease' };
  type Managed = { identity:string; mac?:string; scopeId:number; scopeName:string; sourceIp:string; currentIp:string; credentialProfile:string; configurationStatus:string; onlineStatus:string; redfishStatus:string; authenticationStatus:string; lastCheckedAt?:number };
  type Profile = { name:string; username:string };
  type JobLog = { timestampMs:number; message:string };
  type Row = { identity:string; candidate?:Candidate; managed?:Managed; sourceIp:string; address:string; mac?:string; scopeName:string; subnet?:string; prefix?:number; frozen:boolean };

  let tab:'inventory'|'connection'|'profiles' = 'inventory';
  let lessorUrl = 'http://127.0.0.1:8080';
  let scopeId = 1;
  let targetPrefix = 24;
  let targetGateway = '';
  let candidates:Candidate[] = [];
  let managed:Managed[] = [];
  let profiles:Profile[] = [];
  let rows:Row[] = [];
  let targets:Record<string,string> = {};
  let picked:Record<string,boolean> = {};
  let profileByRow:Record<string,string> = {};
  let manualIp = '';
  let manualMac = '';
  let manualProfile = '';
  let editing = '';
  let editAddress = '';
  let profileName = '';
  let profileUsername = '';
  let profileCurrentPassword = '';
  let profileNewPassword = '';
  let restoreProfileName = '';
  let loading = false;
  let executing = false;
  let savingConnection = false;
  let message = '正在从 lessor 读取已确认 BMC。';
  let error = '';
  let progress = '';
  let executionLogs:JobLog[] = [];
  let showAbout = false;

  onMount(async () => { await defaults(); await Promise.all([load(), inventory(), loadProfiles()]); });

  async function json(response:Response) { try { return await response.json(); } catch { return {}; } }
  function identityFor(candidate:Candidate) { return (candidate.mac ?? `scope-${candidate.scopeId}-ip-${candidate.ip}`).toLowerCase(); }
  function candidateLabel(candidate:Candidate) { return candidate.source === 'relayDhcpLease' ? 'DHCP Relay 租约候选；执行前会以 Redfish 确认' : 'lessor 已确认 BMC'; }
  function rebuildRows() {
    const merged = new Map<string, Row>();
    for (const item of managed) merged.set(item.identity.toLowerCase(), { identity:item.identity, managed:item, sourceIp:item.sourceIp, address:item.currentIp, mac:item.mac, scopeName:item.scopeName, frozen:item.configurationStatus === 'completed' });
    for (const candidate of candidates) {
      const identity = identityFor(candidate), current = merged.get(identity);
      merged.set(identity, current ? { ...current, candidate:current.frozen ? undefined : candidate, sourceIp:candidate.ip, mac:candidate.mac ?? current.mac, scopeName:candidate.scopeName, subnet:candidate.subnet, prefix:candidate.prefix } : { identity, candidate, sourceIp:candidate.ip, address:candidate.ip, mac:candidate.mac, scopeName:candidate.scopeName, subnet:candidate.subnet, prefix:candidate.prefix, frozen:false });
    }
    rows = [...merged.values()].sort((a,b) => Number(b.frozen)-Number(a.frozen) || a.address.localeCompare(b.address));
    targets = Object.fromEntries(rows.map(row => [row.identity, targets[row.identity] ?? (row.frozen ? row.address : '')]));
    picked = Object.fromEntries(rows.map(row => [row.identity, picked[row.identity] ?? false]));
    profileByRow = Object.fromEntries(rows.map(row => [row.identity, profileByRow[row.identity] ?? row.managed?.credentialProfile ?? '']));
  }
  async function defaults() {
    try { const response = await fetch(`${base}/api/v1/settings/defaults`); if (!response.ok) return; const {defaults:value} = await response.json(); lessorUrl=value.lessorUrl; scopeId=value.scopeId; targetPrefix=value.targetPrefix; targetGateway=value.targetGateway; } catch {}
  }
  async function saveConnection() {
    savingConnection = true; error='';
    try { const response = await fetch(`${base}/api/v1/settings/defaults`, {method:'PUT', headers:{'content-type':'application/json'}, body:JSON.stringify({lessorUrl,scopeId,username:'',targetPrefix,targetGateway})}); if (!response.ok) throw Error('无法保存全局连接设置'); message='已保存全局连接与网络默认值。'; } catch(reason) { error=reason instanceof Error ? reason.message : '保存失败'; } finally { savingConnection=false; }
  }
  function requireArray(value:unknown, label:string): any[] {
    if (!Array.isArray(value)) throw Error(`${label}返回了无效的数据格式，请确认桌面端本地服务已升级。`);
    return value;
  }
  async function load() {
    const query = new URLSearchParams({lessorUrl,scopeId:String(scopeId)});
    const response = await fetch(`${base}/api/v1/candidates?${query}`), value = await json(response);
    if (!response.ok) throw Error(value.error ?? '无法读取 lessor BMC 列表');
    candidates=requireArray(value,'lessor BMC 列表') as Candidate[]; rebuildRows();
  }
  async function inventory() { const response=await fetch(`${base}/api/v1/managed-bmcs`), value=await json(response); if (!response.ok) throw Error(value.error ?? '无法读取本地 BMC 清单'); managed=requireArray(value,'本地 BMC 清单') as Managed[]; rebuildRows(); }
  async function loadProfiles() { const response=await fetch(`${base}/api/v1/credential-profiles`), value=await json(response); if (!response.ok) throw Error(value.error ?? '无法读取凭据档案'); profiles=requireArray(value,'凭据档案') as Profile[]; }
  async function refresh() {
    loading=true; error='';
    try {
      await Promise.all([load(), inventory(), loadProfiles()]);
      const checkable=managed.filter(item => item.credentialProfile && profiles.some(profile => profile.name === item.credentialProfile));
      if (!checkable.length) { message = managed.length ? '请先为清单中的 BMC 选择一个凭据档案。' : candidates.length ? `已读取 ${candidates.length} 台待配置 BMC。` : '当前没有 BMC。'; return; }
      const failed:string[]=[];
      for (const [index,item] of checkable.entries()) { progress=`检查 ${index+1}/${checkable.length}：${item.currentIp}`; try { const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/check`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:item.credentialProfile})}); if(!response.ok) failed.push(item.currentIp); } catch { failed.push(item.currentIp); } }
      await inventory(); message=failed.length ? `状态检查完成；${failed.join('、')} 未能完成检查。` : `已更新 ${checkable.length} 台 BMC 的在线、Redfish 与认证状态。`;
    } catch(reason) { error=reason instanceof Error ? reason.message : '刷新失败'; } finally { loading=false; progress=''; }
  }
  function appendExecutionLog(message:string) { executionLogs=[...executionLogs,{timestampMs:Date.now(),message}].slice(-200); }
  function mergeJobLogs(job:any, seen:Set<string>) {
    const entries=Array.isArray(job.logs) ? job.logs as JobLog[] : [];
    const unseen=entries.filter(entry=>{
      const key=`${entry.timestampMs}:${entry.message}`;
      if(seen.has(key)) return false;
      seen.add(key); return true;
    });
    if(unseen.length) executionLogs=[...executionLogs,...unseen].slice(-200);
  }
  function timestamp(value:number) { return new Date(value).toLocaleTimeString('zh-CN',{hour12:false}); }
  async function wait(job:any, seen:Set<string>) { mergeJobLogs(job,seen); while(['queued','running'].includes(job.state)) { await new Promise(resolve=>setTimeout(resolve,1500)); job=await json(await fetch(`${base}/api/v1/jobs/${job.id}`)); mergeJobLogs(job,seen); } return job; }
  async function execute() {
    const selected=rows.filter(row=>row.candidate && !row.frozen && picked[row.identity]);
    if(!selected.length || !targetGateway || selected.some(row=>!targets[row.identity] || !profileByRow[row.identity])) { error='请勾选 BMC，并为每台填写目标 IPv4、选择凭据档案。'; return; }
    executing=true; error=''; executionLogs=[]; appendExecutionLog(`批量配置开始：共 ${selected.length} 台 BMC`); const failed:string[]=[];
    for(const [index,row] of selected.entries()) {
      const candidate=row.candidate!, profileName=profileByRow[row.identity]; progress=`${index+1}/${selected.length}：${candidate.ip} → ${targets[row.identity]}`;
      try {
        appendExecutionLog(`${candidate.ip}：正在读取 HTTPS 证书并生成配置任务`);
        const certificate=await fetch(`${base}/api/v1/certificates/probe`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({lessorUrl,scopeId,candidateIp:candidate.ip})}), certificateValue:any=await json(certificate); if(!certificate.ok) throw Error(certificateValue.error ?? '无法读取 HTTPS 证书');
        const plan=await fetch(`${base}/api/v1/provision/plan`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({lessorUrl,scopeId,candidateIp:candidate.ip,targetNetwork:{address:targets[row.identity],prefix:targetPrefix,gateway:targetGateway},certificateFingerprint:certificateValue.fingerprint.sha256,passwordChange:false,credentialProfile:profileName})}), planned:any=await json(plan); if(!plan.ok) throw Error(planned.details?.reason ?? planned.error ?? '无法生成内部配置');
        const apply=await fetch(`${base}/api/v1/provision/plans/${planned.planId}/apply`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})}), submitted:any=await json(apply); if(!apply.ok) throw Error(submitted.error ?? '无法提交'); const completed=await wait(submitted,new Set<string>()); if(completed.state!=='completed') throw Error(completed.error ?? '配置失败');
      } catch(reason) { const detail=reason instanceof Error ? reason.message : '失败'; appendExecutionLog(`${candidate.ip}：配置失败：${detail}`); failed.push(`${candidate.ip}：${detail}`); }
    }
    await Promise.all([inventory(), loadProfiles()]); executing=false; progress=''; appendExecutionLog(`批量任务完成：成功 ${selected.length-failed.length} 台，失败 ${failed.length} 台`); message=`批量任务完成：成功 ${selected.length-failed.length} 台，失败 ${failed.length} 台。`; if(failed.length) error=failed.join('；');
  }
  async function selectProfile(row:Row, name:string) {
    profileByRow={...profileByRow,[row.identity]:name};
    if(!row.managed) return;
    const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(row.managed.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:name})});
    if(!response.ok) error='无法保存该 BMC 的凭据档案选择'; else await inventory();
  }
  async function addManual() { if(!manualIp){error='请填写 BMC IPv4 地址。';return;} const response=await fetch(`${base}/api/v1/managed-bmcs`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({currentIp:manualIp,mac:manualMac||undefined})}), value:any=await json(response); if(!response.ok){error=value.error??'无法添加 BMC';return;} if(manualProfile) await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(value.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:manualProfile})}); manualIp='';manualMac='';await inventory();message='已加入本地 BMC 清单。'; }
  async function saveAddress(item:Managed) { const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({currentIp:editAddress})}), value:any=await json(response); if(!response.ok){error=value.error??'无法更新访问地址';return;} editing='';await inventory();message='已更新本地访问地址。'; }
  async function remove(item:Managed) { if(!confirm(`删除本地清单中的 ${item.currentIp}？不会修改 BMC。`))return; const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'DELETE'});if(!response.ok){error='无法删除本地清单记录';return;}await inventory();message='已删除本地清单记录。'; }
  async function saveProfile() { if(!profileName || !profileUsername || !profileCurrentPassword){error='请填写档案名称、用户名和当前密码。';return;} const response=await fetch(`${base}/api/v1/credential-profiles`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:profileName,username:profileUsername,currentPassword:profileCurrentPassword,newPassword:profileNewPassword})});if(!response.ok){error='无法保存凭据档案';return;}profileName='';profileUsername='';profileCurrentPassword='';profileNewPassword='';await loadProfiles();message='凭据档案已安全保存到 Windows 凭据管理器。'; }
  async function restoreProfile() { if(!restoreProfileName.trim()){error='请输入需要恢复的档案名称。';return;} error=''; const name=restoreProfileName.trim(), response=await fetch(`${base}/api/v1/credential-profiles/${encodeURIComponent(name)}/restore`,{method:'POST'}), value=await json(response); if(!response.ok){error=value.error??'没有找到对应的系统凭据档案。';return;} restoreProfileName='';await loadProfiles();message=`已恢复凭据档案 ${value.name}；密码未显示、导出或改写。`; }
  async function removeProfile(name:string) { if(!confirm(`删除凭据档案 ${name}？已关联的 BMC 将不能再自动检查或配置。`))return;const response=await fetch(`${base}/api/v1/credential-profiles/${encodeURIComponent(name)}`,{method:'DELETE'});if(!response.ok){error='无法删除凭据档案';return;}await loadProfiles();message='已删除凭据档案。'; }
  function setTarget(identity:string,value:string){targets={...targets,[identity]:value};} function choose(identity:string,value:boolean){picked={...picked,[identity]:value};}
  async function open(ip:string){try{if('__TAURI_INTERNALS__' in window)await openUrl(`https://${ip}`);else window.open(`https://${ip}`,'_blank')}catch{error='无法使用默认浏览器打开 BMC 地址'}}
  const label=(value:string)=>({online:'在线',offline:'离线',reachable:'可用',unreachable:'不可达',success:'成功',failed:'失败',unknown:'未检查',completed:'已完成',manual:'手动记录',network_changed_unverified:'已变更，待验证'} as Record<string,string>)[value]??value;
</script>

<main>
  <header><div><h1>bmc-provisioner <button class="version" onclick={()=>showAbout=true}>v0.1.7</button></h1></div><span class="local">已连接</span></header>
  <nav aria-label="主导航"><button class:active={tab==='inventory'} onclick={()=>tab='inventory'}>BMC 清单 <span>{rows.length}</span></button><button class:active={tab==='connection'} onclick={()=>tab='connection'}>连接设置</button><button class:active={tab==='profiles'} onclick={()=>tab='profiles'}>凭据档案 <span>{profiles.length}</span></button></nav>

  {#if tab==='inventory'}
    <section class="workspace"><div class="section-title"><div><h2>BMC 清单与访问状态</h2><p>来自 lessor 的动态发现与本地配置记录会按 MAC 合并；Relay 租约将在执行前由 Redfish 确认。</p></div><button onclick={refresh} disabled={loading||executing}>{loading?(progress||'刷新中…'):'刷新并检查状态'}</button></div>
    {#if rows.length}<div class="bmc-table"><div class="bmc-row table-heading"><span>选择 / BMC</span><span>MAC / 作用域</span><span>凭据档案</span><span>目标静态 IPv4 / 访问</span><span>状态</span></div>{#each rows as row}<div class:frozen={row.frozen} class="bmc-row"><label class="pick"><input type="checkbox" checked={picked[row.identity]} disabled={row.frozen||!row.candidate} onchange={event=>choose(row.identity,event.currentTarget.checked)}/><span><strong>{row.frozen?row.address:row.sourceIp}</strong><small>{row.frozen?`已冻结；来源 ${row.sourceIp}`:row.candidate?candidateLabel(row.candidate):'本地历史记录'}</small></span></label><span><code>{row.mac??'MAC 未返回'}</code><small>{row.scopeName}{row.subnet?` / ${row.subnet}/${row.prefix}`:''}</small></span><select value={profileByRow[row.identity]??''} onchange={event=>selectProfile(row,event.currentTarget.value)}><option value="">选择档案</option>{#each profiles as item}<option value={item.name}>{item.name} · {item.username}</option>{/each}</select><span>{#if row.managed&&editing===row.managed.identity}<input bind:value={editAddress}/><button onclick={()=>saveAddress(row.managed!)}>保存</button>{:else}<input value={targets[row.identity]??''} disabled={row.frozen||!row.candidate} oninput={event=>setTarget(row.identity,event.currentTarget.value)} placeholder="例如 172.16.40.200"/>{#if row.managed}<a href={`https://${row.address}`} onclick={event=>{event.preventDefault();void open(row.address)}}>https://{row.address}</a>{/if}{/if}</span>{#if row.managed}<span><strong>{label(row.managed.configurationStatus)}{row.frozen?' · 已冻结':''}</strong><small>{label(row.managed.onlineStatus)} / {label(row.managed.redfishStatus)} / {label(row.managed.authenticationStatus)}</small><span class="row-actions"><button onclick={()=>{editing=row.managed!.identity;editAddress=row.managed!.currentIp}}>编辑地址</button><button class="text-danger" onclick={()=>remove(row.managed!)}>删除</button></span></span>{:else}<span><strong>待配置</strong><small>配置后自动记录访问状态</small></span>{/if}</div>{/each}</div><div class="batch-bar"><span>目标网络：/{targetPrefix}，网关 {targetGateway||'未设置'}</span><button class="danger" onclick={execute} disabled={executing}>执行已勾选 BMC 的 IP 变更配置</button></div>{:else}<p class="muted">尚未读取到 BMC；请检查 lessor 连接设置。</p>{/if}
    <div class="manual-add"><strong>手动加入清单</strong><input bind:value={manualIp} placeholder="BMC IPv4，例如 172.16.40.200"/><input bind:value={manualMac} placeholder="MAC（可选）"/><select bind:value={manualProfile}><option value="">凭据档案（可选）</option>{#each profiles as item}<option value={item.name}>{item.name}</option>{/each}</select><button class="secondary" onclick={addManual}>加入清单</button></div></section>
  {:else if tab==='connection'}
    <section class="settings-page"><div class="section-title"><div><h2>连接设置</h2><p>lessor 是全局的 BMC 动态发现来源。</p></div></div><div class="setting-grid"><label>lessor 地址<input bind:value={lessorUrl} placeholder="http://127.0.0.1:8080"/></label><label>作用域 ID<input bind:value={scopeId} type="number" min="1"/></label></div><div class="setting-grid network"><label>默认 IPv4 前缀<input bind:value={targetPrefix} type="number" min="1" max="32"/></label><label>默认网关<input bind:value={targetGateway} placeholder="172.16.40.254"/></label></div><button class="primary" onclick={saveConnection} disabled={savingConnection}>{savingConnection?'保存中…':'保存连接设置'}</button></section>
  {:else}
    <section class="settings-page"><div class="section-title"><div><h2>凭据档案</h2><p>档案名称和用户名保存到本机数据目录；桌面端密码仅保存到 Windows 凭据管理器。Docker 使用当前服务会话，服务重启后需要重新填写密码。</p></div></div><div class="profile-form"><label>档案名称<input bind:value={profileName} placeholder="例如 default、rack-a"/></label><label>用户名<input bind:value={profileUsername} placeholder="root"/></label><label>当前密码<input bind:value={profileCurrentPassword} type="password"/></label><label>新密码 <small>首次强制改密时使用</small><input bind:value={profileNewPassword} type="password"/></label><button class="primary" onclick={saveProfile}>保存档案</button></div><div class="profile-recovery"><span><strong>恢复已有 Windows 档案</strong><small>升级前的密码仍在凭据管理器时，输入原档案名即可恢复其名称和用户名；不会显示、导出或改写密码。</small></span><input bind:value={restoreProfileName} placeholder="例如 asrr-default" onkeydown={event=>{if(event.key==='Enter')void restoreProfile()}}/><button class="secondary" onclick={restoreProfile}>恢复档案</button></div>{#if profiles.length}<div class="profile-list">{#each profiles as item}<div><span><strong>{item.name}</strong><small>{item.username} · 系统凭据管理器或当前服务会话</small></span><button class="text-danger" onclick={()=>removeProfile(item.name)}>删除</button></div>{/each}</div>{:else}<p class="muted">还没有凭据档案。先创建一个档案，或恢复已有的 Windows 档案，再回到 BMC 清单逐行选择。</p>{/if}</section>
  {/if}
  {#if executionLogs.length}<section class="execution-log" aria-live="polite"><div><h2>执行日志</h2><small>{executing ? '任务执行中，日志会持续更新' : '本次任务已结束'}</small></div><ol>{#each executionLogs as item}<li><time>{timestamp(item.timestampMs)}</time><span>{item.message}</span></li>{/each}</ol></section>{/if}
  <footer aria-live="polite">{#if error}<p class="error">{error}</p>{/if}<p>{message}</p></footer>
  {#if showAbout}<UpdateDialog version="0.1.7" onclose={()=>showAbout=false}/>{/if}
</main>
