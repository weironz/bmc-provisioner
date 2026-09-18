<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { openUrl } from '@tauri-apps/plugin-opener';
  import UpdateDialog from './lib/UpdateDialog.svelte';
  import { desktopVersion } from './lib/desktop';

  // The desktop WebView origin is a Tauri-owned asset origin, not bmc-provisionerd.
  // Both the packaged desktop app and Vite development UI therefore use the local API
  // service explicitly.  Using window.location.origin here makes a packaged build fetch
  // its own HTML fallback and later try to iterate an object as the BMC candidate list.
  const base = 'http://127.0.0.1:6770';
  type Candidate = { scopeId:number; scopeName:string; subnet:string; prefix:number; ip:string; mac?:string; source:'confirmedDiscovery'|'relayDhcpLease' };
  type Managed = { identity:string; displayName:string; clusterId?:number; mac?:string; scopeId:number; scopeName:string; sourceIp:string; currentIp:string; credentialProfile:string; configurationStatus:string; onlineStatus:string; redfishStatus:string; authenticationStatus:string; lastCheckedAt?:number };
  type Profile = { name:string; username:string };
  type Cluster = { id:number; name:string; createdAt:number };
  type JobLog = { timestampMs:number; message:string };
  type PowerAction = 'on'|'shutdown'|'restart';
  type PowerStatus = { systemUri:string; powerState?:string; supportedActions:PowerAction[] };
  type ManagedPowerStatus = { managed:Managed; power?:PowerStatus; certificateFingerprint?:{sha256:string}; certificateTrustRequired:boolean; detail?:string };
  type Row = { identity:string; candidate?:Candidate; managed?:Managed; sourceIp:string; address:string; mac?:string; scopeName:string; subnet?:string; prefix?:number; frozen:boolean };

  let tab = $state<'inventory'|'connection'|'profiles'|'management'|'clusters'>('inventory');
  let lessorUrl = $state('http://127.0.0.1:8080');
  let scopeId = $state(1);
  let targetPrefix = $state(24);
  let targetGateway = $state('');
  let batchConcurrency = $state(4);
  let candidates = $state<Candidate[]>([]);
  let managed = $state<Managed[]>([]);
  let profiles = $state<Profile[]>([]);
  let clusters = $state<Cluster[]>([]);
  let rows = $state<Row[]>([]);
  let targets = $state<Record<string,string>>({});
  let picked = $state<Record<string,boolean>>({});
  let profileByRow = $state<Record<string,string>>({});
  let manualIp = $state('');
  let manualMac = $state('');
  let manualProfile = $state('');
  let editing = $state('');
  let editAddress = $state('');
  let profileName = $state('');
  let profileUsername = $state('');
  let profileCurrentPassword = $state('');
  let profileNewPassword = $state('');
  let restoreProfileName = $state('');
  let loading = $state(false);
  let inspecting = $state(false);
  let executing = $state(false);
  let savingConnection = $state(false);
  let message = $state('正在从 lessor 读取已确认 BMC。');
  let error = $state('');
  let progress = $state('');
  let executionLogs = $state<JobLog[]>([]);
  let showAbout = $state(false);
  let currentVersion = $state('…');
  let managementPicked = $state<Record<string,boolean>>({});
  let managementStatus = $state<Record<string,ManagedPowerStatus>>({});
  let managementBusy = $state(false);
  let managementAddName = $state('');
  let managementAddIp = $state('');
  let managementAddMac = $state('');
  let managementAddProfile = $state('');
  let managementEditing = $state('');
  let managementEditName = $state('');
  let managementEditIp = $state('');
  let managementEditProfile = $state('');
  let managementClusterFilter = $state('all');
  let managementBatchCluster = $state('');
  let managementAddCluster = $state('');
  let managementEditCluster = $state('');
  let clusterName = $state('');
  let editingCluster = $state<number|undefined>();
  let clusterEditName = $state('');
  let probeIntervalSecs = $state(30);
  let probeTimer: ReturnType<typeof setInterval> | null = null;
  let probing = false;

  function loadProbeInterval() {
    try {
      const saved = localStorage.getItem('bmc_probe_interval');
      if (saved !== null) {
        const parsed = Number(saved);
        if (!isNaN(parsed) && [0, 15, 30, 60, 120].includes(parsed)) {
          probeIntervalSecs = parsed;
        }
      }
    } catch {}
  }
  function setProbeInterval(secs: number) {
    probeIntervalSecs = secs;
    try { localStorage.setItem('bmc_probe_interval', String(secs)); } catch {}
    restartProbeTimer();
  }
  function restartProbeTimer() {
    console.log('[Timer] Restarting timer, interval:', probeIntervalSecs, 'seconds');
    if (probeTimer) {
      clearInterval(probeTimer);
      probeTimer = null;
    }
    if (probeIntervalSecs > 0) {
      console.log('[Timer] Setting up interval for', probeIntervalSecs, 'seconds');
      probeTimer = setInterval(() => {
        console.log('[Timer] Interval fired, managed.length:', managed.length, 'probing:', probing, 'managementBusy:', managementBusy, 'executing:', executing);
        if (managed.length > 0) {
          // 强制刷新：即使标志显示忙碌，超过 30 秒也应该重置并重试
          if (probing) {
            console.warn('[Auto-refresh] probing flag stuck, resetting');
            probing = false;
          }
          void probeManagement(undefined, true);
        }
      }, probeIntervalSecs * 1000);
      console.log('[Timer] Interval set successfully');
    } else {
      console.log('[Timer] Auto-refresh disabled (interval is 0)');
    }
  }

  onDestroy(() => {
    if (probeTimer) {
      clearInterval(probeTimer);
      probeTimer = null;
    }
  });

  onMount(async () => {
    loadProbeInterval();
    currentVersion = await desktopVersion() ?? '浏览器版';
    await defaults();
    await Promise.all([load(), inventory(), loadProfiles(), loadClusters()]);
    if (managed.length > 0) {
      void probeManagement(undefined, true);
    }
    restartProbeTimer();
  });

  async function json(response:Response) { try { return await response.json(); } catch { return {}; } }
  function identityFor(candidate:Candidate) { return (candidate.mac ?? `scope-${candidate.scopeId}-ip-${candidate.ip}`).toLowerCase(); }
  function candidateLabel(candidate:Candidate) { return candidate.source === 'relayDhcpLease' ? 'DHCP Relay 租约候选；执行前会以 Redfish 确认' : 'lessor 已确认 BMC'; }
  function isFrozen(status:string) { return status === 'completed' || status === 'adopted_static'; }
  function rebuildRows() {
    const merged = new Map<string, Row>();
    for (const item of managed) merged.set(item.identity.toLowerCase(), { identity:item.identity, managed:item, sourceIp:item.sourceIp, address:item.currentIp, mac:item.mac, scopeName:item.scopeName, frozen:isFrozen(item.configurationStatus) });
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
    try { const response = await fetch(`${base}/api/v1/settings/defaults`); if (!response.ok) return; const {defaults:value} = await response.json(); lessorUrl=value.lessorUrl; scopeId=value.scopeId; targetPrefix=value.targetPrefix; targetGateway=value.targetGateway; batchConcurrency=value.batchConcurrency??4; } catch {}
  }
  async function saveConnection() {
    savingConnection = true; error='';
    try { const response = await fetch(`${base}/api/v1/settings/defaults`, {method:'PUT', headers:{'content-type':'application/json'}, body:JSON.stringify({lessorUrl,scopeId,username:'',targetPrefix,targetGateway,batchConcurrency})}); if (!response.ok) throw Error('无法保存全局连接设置'); message='已保存全局连接、网络默认值与批量并发数。'; } catch(reason) { error=reason instanceof Error ? reason.message : '保存失败'; } finally { savingConnection=false; }
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
  async function inventory() { const response=await fetch(`${base}/api/v1/managed-bmcs`), value=await json(response); if (!response.ok) throw Error(value.error ?? '无法读取本地 BMC 清单'); managed=requireArray(value,'本地 BMC 清单') as Managed[]; managementPicked=Object.fromEntries(managed.map(item=>[item.identity,managementPicked[item.identity]??false])); rebuildRows(); }
  async function loadProfiles() { const response=await fetch(`${base}/api/v1/credential-profiles`), value=await json(response); if (!response.ok) throw Error(value.error ?? '无法读取凭据档案'); profiles=requireArray(value,'凭据档案') as Profile[]; }
  async function loadClusters() { const response=await fetch(`${base}/api/v1/clusters`), value=await json(response); if (!response.ok) throw Error(value.error ?? '无法读取集群'); clusters=requireArray(value,'集群') as Cluster[]; }
  async function refresh() {
    loading=true; error='';
    try {
      await Promise.all([load(), inventory(), loadProfiles(), loadClusters()]);
      const checkable=managed.filter(item => item.credentialProfile && profiles.some(profile => profile.name === item.credentialProfile));
      if (!checkable.length) { message = managed.length ? '请先为清单中的 BMC 选择一个凭据档案。' : candidates.length ? `已读取 ${candidates.length} 台待配置 BMC。` : '当前没有 BMC。'; return; }
      const failed:string[]=[];
      for (const [index,item] of checkable.entries()) { progress=`检查 ${index+1}/${checkable.length}：${item.currentIp}`; try { const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/check`, {method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:item.credentialProfile})}); if(!response.ok) failed.push(item.currentIp); } catch { failed.push(item.currentIp); } }
      await inventory(); message=failed.length ? `状态检查完成；${failed.join('、')} 未能完成检查。` : `已更新 ${checkable.length} 台 BMC 的在线、Redfish 与认证状态。`;
    } catch(reason) { error=reason instanceof Error ? reason.message : '刷新失败'; } finally { loading=false; progress=''; }
  }
  function appendExecutionLog(message:string) { executionLogs=[...executionLogs,{timestampMs:Date.now(),message}].slice(-200); }
  function mergeJobLogs(job:any, seen:Set<string>, ip:string) {
    const entries=Array.isArray(job.logs) ? job.logs as JobLog[] : [];
    const unseen=entries.filter(entry=>{
      const key=`${entry.timestampMs}:${entry.message}`;
      if(seen.has(key)) return false;
      seen.add(key); return true;
    });
    if(unseen.length) executionLogs=[...executionLogs,...unseen.map(entry=>({...entry,message:`${ip}：${entry.message}`}))].slice(-200);
  }
  function timestamp(value:number) { return new Date(value).toLocaleTimeString('zh-CN',{hour12:false}); }
  async function wait(job:any, seen:Set<string>, ip:string) { mergeJobLogs(job,seen,ip); while(['queued','running'].includes(job.state)) { await new Promise(resolve=>setTimeout(resolve,1500)); job=await json(await fetch(`${base}/api/v1/jobs/${job.id}`)); mergeJobLogs(job,seen,ip); } return job; }
  async function runWithLimit<T>(items:T[], limit:number, work:(item:T,index:number)=>Promise<void>) { let next=0; const workers=Array.from({length:Math.min(limit,items.length)},async()=>{while(next<items.length){const index=next++;await work(items[index],index);}}); await Promise.all(workers); }
  async function inspectSelected() {
    const selected=rows.filter(row=>row.candidate && !row.frozen && picked[row.identity]);
    if(!selected.length || selected.some(row=>!profileByRow[row.identity])) { error='请勾选待配置 BMC，并为每台选择凭据档案后再核验。'; return; }
    inspecting=true; error=''; const adopted:string[]=[]; const dhcp:string[]=[]; const incomplete:string[]=[]; const failed:string[]=[];
    try {
      await runWithLimit(selected,batchConcurrency,async(row,index)=>{
        const candidate=row.candidate!, profileName=profileByRow[row.identity]; progress=`核验 ${index+1}/${selected.length}：${candidate.ip}`;
        try {
          const response=await fetch(`${base}/api/v1/candidates/inspect-network`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({lessorUrl,scopeId,candidateIp:candidate.ip,credentialProfile:profileName})}), value:any=await json(response);
          if(!response.ok) throw Error(value.error??'无法完成 Redfish 网络核验');
          if(value.mode==='static') adopted.push(candidate.ip);
          else if(value.mode==='dhcp') dhcp.push(candidate.ip);
          else incomplete.push(candidate.ip);
        } catch(reason) { failed.push(`${candidate.ip}：${reason instanceof Error?reason.message:'核验失败'}`); }
      });
      await inventory();
      message=`核验完成：已纳管静态 IP ${adopted.length} 台，DHCP 待配置 ${dhcp.length} 台${incomplete.length?`，静态详情不完整 ${incomplete.length} 台`:''}${failed.length?`，失败 ${failed.length} 台`:''}。`;
      if(failed.length) error=failed.join('；');
    } finally { inspecting=false; progress=''; }
  }
  async function execute() {
    const selected=rows.filter(row=>row.candidate && !row.frozen && picked[row.identity]);
    if(!selected.length || !targetGateway || selected.some(row=>!targets[row.identity] || !profileByRow[row.identity])) { error='请勾选 BMC，并为每台填写目标 IPv4、选择凭据档案。'; return; }
    executing=true; error=''; executionLogs=[]; appendExecutionLog(`批量配置开始：共 ${selected.length} 台 BMC，预检并发 ${batchConcurrency}，写入并发 ${batchConcurrency}`); const failed:string[]=[]; const plannedJobs:{row:Row;planId:string;ip:string}[]=[];
    await runWithLimit(selected,batchConcurrency,async(row,index)=>{
      const candidate=row.candidate!, profileName=profileByRow[row.identity]; progress=`预检 ${index+1}/${selected.length}：${candidate.ip} → ${targets[row.identity]}`;
      try {
        appendExecutionLog(`${candidate.ip}：正在读取 HTTPS 证书并生成配置任务`);
        const certificate=await fetch(`${base}/api/v1/certificates/probe`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({lessorUrl,scopeId,candidateIp:candidate.ip})}), certificateValue:any=await json(certificate); if(!certificate.ok) throw Error(certificateValue.error ?? '无法读取 HTTPS 证书');
        const plan=await fetch(`${base}/api/v1/provision/plan`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({lessorUrl,scopeId,candidateIp:candidate.ip,targetNetwork:{address:targets[row.identity],prefix:targetPrefix,gateway:targetGateway},certificateFingerprint:certificateValue.fingerprint.sha256,passwordChange:false,credentialProfile:profileName})}), planResponse:any=await json(plan); if(!plan.ok) throw Error(planResponse.details?.reason ?? planResponse.error ?? '无法生成内部配置');
        plannedJobs.push({row,planId:planResponse.planId,ip:candidate.ip}); appendExecutionLog(`${candidate.ip}：预检完成，等待批量写入`);
      } catch(reason) { const detail=reason instanceof Error ? reason.message : '失败'; appendExecutionLog(`${candidate.ip}：配置失败：${detail}`); failed.push(`${candidate.ip}：${detail}`); }
    });
    appendExecutionLog(`预检完成：${plannedJobs.length} 台可执行，${failed.length} 台失败；正在提交写入队列`);
    const jobs:{ip:string;job:any}[]=[];
    await Promise.all(plannedJobs.map(async item=>{try{const apply=await fetch(`${base}/api/v1/provision/plans/${item.planId}/apply`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({})}), submitted:any=await json(apply);if(!apply.ok)throw Error(submitted.error??'无法提交');jobs.push({ip:item.ip,job:submitted});}catch(reason){const detail=reason instanceof Error?reason.message:'失败';appendExecutionLog(`${item.ip}：提交失败：${detail}`);failed.push(`${item.ip}：${detail}`);}}));
    appendExecutionLog(`已提交 ${jobs.length} 个写入任务；静态 IP 写入与新地址验证将交错进行`);
    await Promise.all(jobs.map(async item=>{try{const completed=await wait(item.job,new Set<string>(),item.ip);if(completed.state!=='completed')throw Error(completed.error??'配置失败');}catch(reason){const detail=reason instanceof Error?reason.message:'失败';appendExecutionLog(`${item.ip}：配置失败：${detail}`);failed.push(`${item.ip}：${detail}`);}}));
    await Promise.all([inventory(), loadProfiles()]); executing=false; progress=''; appendExecutionLog(`批量任务完成：成功 ${selected.length-failed.length} 台，失败 ${failed.length} 台`); message=`批量任务完成：成功 ${selected.length-failed.length} 台，失败 ${failed.length} 台。`; if(failed.length) error=failed.join('；');
    if(managed.length) void probeManagement(undefined, true);
  }
  async function selectProfile(row:Row, name:string) {
    profileByRow={...profileByRow,[row.identity]:name};
    if(!row.managed) return;
    const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(row.managed.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:name})});
    if(!response.ok) error='无法保存该 BMC 的凭据档案选择';
    else {
      await inventory();
      const updatedItem = managed.find(item => item.identity.toLowerCase() === row.managed!.identity.toLowerCase());
      if (updatedItem) void probeManagement([updatedItem], true);
    }
  }
  async function addManual() {
    if(!manualIp){error='请填写 BMC IPv4 地址。';return;}
    const response=await fetch(`${base}/api/v1/managed-bmcs`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({currentIp:manualIp,mac:manualMac||undefined})}), value:any=await json(response);
    if(!response.ok){error=value.error??'无法添加 BMC';return;}
    if(manualProfile) await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(value.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:manualProfile})});
    manualIp='';manualMac='';await inventory();message='已加入本地 BMC 清单。';
    const newItem = managed.find(item => item.identity.toLowerCase() === value.identity.toLowerCase());
    if (newItem) void probeManagement([newItem], true);
  }
  async function saveAddress(item:Managed) { const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({currentIp:editAddress})}), value:any=await json(response); if(!response.ok){error=value.error??'无法更新访问地址';return;} editing='';await inventory();message='已更新本地访问地址。'; }
  async function remove(item:Managed) { if(!confirm(`删除本地清单中的 ${item.currentIp}？不会修改 BMC。`))return; const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'DELETE'});if(!response.ok){error='无法删除本地清单记录';return;}await inventory();message='已删除本地清单记录。'; }
  async function reprovision(item:Managed) { if(!confirm(`解除 ${item.currentIp} 的静态保护？不会立即修改 BMC，之后可重新填写目标 IP 并执行。`))return; const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({allowReprovision:true})}), value:any=await json(response); if(!response.ok){error=value.error??'无法解除静态保护';return;} await inventory(); message='已解除静态保护；尚未向 BMC 写入任何配置。'; }
  async function saveProfile() { if(!profileName || !profileUsername || !profileCurrentPassword){error='请填写档案名称、用户名和当前密码。';return;} const response=await fetch(`${base}/api/v1/credential-profiles`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:profileName,username:profileUsername,currentPassword:profileCurrentPassword,newPassword:profileNewPassword})});if(!response.ok){error='无法保存凭据档案';return;}profileName='';profileUsername='';profileCurrentPassword='';profileNewPassword='';await loadProfiles();message='凭据档案已安全保存到 Windows 凭据管理器。'; }
  async function restoreProfile() { if(!restoreProfileName.trim()){error='请输入需要恢复的档案名称。';return;} error=''; const name=restoreProfileName.trim(), response=await fetch(`${base}/api/v1/credential-profiles/${encodeURIComponent(name)}/restore`,{method:'POST'}), value=await json(response); if(!response.ok){error=value.error??'没有找到对应的系统凭据档案。';return;} restoreProfileName='';await loadProfiles();message=`已恢复凭据档案 ${value.name}；密码未显示、导出或改写。`; }
  async function removeProfile(name:string) { if(!confirm(`删除凭据档案 ${name}？已关联的 BMC 将不能再自动检查或配置。`))return;const response=await fetch(`${base}/api/v1/credential-profiles/${encodeURIComponent(name)}`,{method:'DELETE'});if(!response.ok){error='无法删除凭据档案';return;}await loadProfiles();message='已删除凭据档案。'; }
  function chooseManaged(identity:string,value:boolean){managementPicked={...managementPicked,[identity]:value};}
  function clusterFor(item:Managed) { return clusters.find(cluster=>cluster.id===item.clusterId); }
  function clusterLabel(item:Managed) { return clusterFor(item)?.name ?? '未分配集群'; }
  function clusterSize(clusterId:number) { return managed.filter(item=>item.clusterId===clusterId).length; }
  function filteredManaged() { return managementClusterFilter==='all' ? managed : managementClusterFilter==='unassigned' ? managed.filter(item=>!item.clusterId) : managed.filter(item=>item.clusterId===Number(managementClusterFilter)); }
  function allFilteredManagedPicked() { const visible=filteredManaged(); return visible.length>0 && visible.every(item=>managementPicked[item.identity]); }
  function chooseAllFilteredManaged(value:boolean) { managementPicked={...managementPicked,...Object.fromEntries(filteredManaged().map(item=>[item.identity,value]))}; }
  function pickedManaged() { return managed.filter(item=>managementPicked[item.identity]); }
  async function managementStatusOne(item:Managed, trustCertificate=false) {
    const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/power/status`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({trustCertificate})});
    const value:any=await json(response);
    if(!response.ok) throw Error(value.error??'无法读取 BMC 管理状态');
    managementStatus={...managementStatus,[item.identity]:value as ManagedPowerStatus};
  }
  async function probeManagement(only?:Managed[], silent=false) {
    const items=only??managed;
    if(!items.length){
      if(!silent) message='还没有本地 BMC 清单；可先手动加入，或从 lessor 发现后执行配置。';
      return;
    }
    if(silent && (probing || managementBusy || executing)) {
      console.log('[Auto-refresh] Skipped - busy:', { probing, managementBusy, executing });
      return;
    }
    if(probing) return;
    console.log('[Auto-refresh] Starting probe for', items.length, 'BMCs, silent:', silent);
    probing=true;
    if(!silent) { managementBusy=true; error=''; }
    const failed:string[]=[];
    try {
      await runWithLimit(items,Math.min(batchConcurrency,4),async(item,index)=>{
        if(!silent) progress=`检查 ${index+1}/${items.length}：${item.currentIp}`;
        try {
          await managementStatusOne(item);
        } catch(reason) {
          const detail=reason instanceof Error?reason.message:'状态检查失败';
          managementStatus={...managementStatus,[item.identity]:{managed:item,certificateTrustRequired:false,detail}};
          failed.push(item.currentIp);
        }
      });
      await inventory();
      console.log('[Auto-refresh] Completed, failed:', failed.length);
      if(!silent) {
        message=failed.length?`状态刷新完成；${failed.length} 台未能读取 Redfish 状态。`:`已更新 ${items.length} 台 BMC 的在线、Redfish、认证和电源状态。`;
        if(failed.length) error=`无法检查：${failed.join('、')}`;
      }
    } finally {
      probing=false;
      if(!silent) { managementBusy=false; progress=''; }
    }
  }
  async function refreshManagement(only?:Managed) {
    await probeManagement(only?[only]:undefined, false);
  }
  async function trustManagementCertificate(item:Managed) {
    const pending=managementStatus[item.identity]; const fingerprint=pending?.certificateFingerprint?.sha256;
    if(!fingerprint || !confirm(`确认信任 ${item.currentIp} 的 BMC HTTPS 证书？\nSHA-256：${fingerprint}`)) return;
    managementBusy=true; error='';
    try { await managementStatusOne(item,true); await inventory(); message=`已保存 ${item.currentIp} 的证书指纹，并读取 Redfish 电源能力。`; } catch(reason) { error=reason instanceof Error?reason.message:'无法确认 BMC 证书'; } finally { managementBusy=false; }
  }
  function supportsPower(item:Managed,action:PowerAction) {
    const status = managementStatus[item.identity];
    if (!status?.power?.supportedActions.includes(action)) return false;

    // 根据当前电源状态智能禁用不适用的操作
    const powerState = status.power.powerState?.toLowerCase();
    if (action === 'on' && powerState === 'on') return false;  // 已开机，禁用开机按钮
    if (action === 'shutdown' && powerState === 'off') return false;  // 已关机，禁用关机按钮

    return true;
  }
  const powerActionNames:{[key in PowerAction]:string}={on:'开机',shutdown:'关机',restart:'重启'};
  // Explains a disabled power button instead of leaving the operator to guess.
  function powerHint(item:Managed,action:PowerAction) {
    if(supportsPower(item,action)) return `通过 Redfish ComputerSystem.Reset 执行${powerActionNames[action]}`;
    const status=managementStatus[item.identity];
    if(!status) return '尚未探测状态；先点「刷新管理状态」';
    if(status.certificateTrustRequired) return '需先确认该 BMC 的 HTTPS 证书指纹';
    if(!status.power) return status.detail??'未能读取 Redfish 电源状态';
    return `该 BMC 的 Redfish 未声明可用于${powerActionNames[action]}的 ResetType`;
  }
  // Acts on the clicked row only. The batch bar keeps using executeManagementPower.
  async function powerOne(item:Managed,action:PowerAction) {
    if(!confirm(`确认对 ${item.displayName||item.currentIp} 执行${powerActionNames[action]}？\n仅会发送 Redfish 电源操作，不修改网络或凭据。`)) return;
    managementBusy=true; error='';
    try {
      const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/power`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action})}),value:any=await json(response);
      if(!response.ok) throw Error(value.error??'操作失败');
      const previous=managementStatus[item.identity];
      managementStatus={...managementStatus,[item.identity]:{managed:value.managed,power:previous?.power,certificateTrustRequired:false,detail:`已提交${powerActionNames[action]}（${value.command.resetType}）`}};
      await inventory();
      message=`${item.currentIp}：已提交${powerActionNames[action]}（ResetType ${value.command.resetType}）。`;
    } catch(reason) {
      error=`${item.currentIp}：${reason instanceof Error?reason.message:'电源操作失败'}`;
    } finally {
      managementBusy=false;
      setTimeout(()=>void probeManagement([item],true),2500);
    }
  }
  async function executeManagementPower(action:PowerAction) {
    const selected=managed.filter(item=>managementPicked[item.identity]);
    if(!selected.length){error='请至少勾选一台 BMC。';return;}
    const eligible=selected.filter(item=>supportsPower(item,action));
    if(!eligible.length){error='所选 BMC 尚未完成状态探测，或其 Redfish 未声明支持此操作。';return;}
    const names=powerActionNames;
    if(!confirm(`确认对 ${eligible.length} 台 BMC 执行批量${names[action]}？\n仅会发送 Redfish 电源操作，不修改网络或凭据。`)) return;
    managementBusy=true; error=''; const failed:string[]=[];
    try { await runWithLimit(eligible,Math.min(batchConcurrency,4),async(item,index)=>{progress=`${names[action]} ${index+1}/${eligible.length}：${item.currentIp}`;const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/power`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action})}),value:any=await json(response);if(!response.ok){failed.push(`${item.currentIp}：${value.error??'操作失败'}`);return;}const previous=managementStatus[item.identity];managementStatus={...managementStatus,[item.identity]:{managed:value.managed,power:previous?.power,certificateTrustRequired:false,detail:`已提交${names[action]}（${value.command.resetType}）`}};}); await inventory(); message=`批量${names[action]}已提交：成功 ${eligible.length-failed.length} 台，失败 ${failed.length} 台。`;if(failed.length)error=failed.join('；'); } finally {managementBusy=false;progress='';setTimeout(()=>{if(eligible.length)void probeManagement(eligible,true);},2500);}
  }
  async function addManagementBmc() {
    if(!managementAddIp){error='请填写 BMC IPv4 地址。';return;}
    const response=await fetch(`${base}/api/v1/managed-bmcs`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({currentIp:managementAddIp,mac:managementAddMac||undefined,scopeName:'BMC 管理',displayName:managementAddName||undefined})}), value:any=await json(response);
    if(!response.ok){error=value.error??'无法加入 BMC 清单';return;}
    if(managementAddProfile||managementAddCluster){const updated=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(value.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({credentialProfile:managementAddProfile||undefined,clusterId:managementAddCluster?Number(managementAddCluster):undefined})});if(!updated.ok){error='BMC 已加入，但凭据档案或集群归属未保存';}}
    managementAddName='';managementAddIp='';managementAddMac='';managementAddProfile='';managementAddCluster='';await inventory();message='已加入本地 BMC 管理清单。';
    const newItem=managed.find(item=>item.identity.toLowerCase()===value.identity.toLowerCase());
    if(newItem) void probeManagement([newItem],true);
  }
  function beginManagementEdit(item:Managed){managementEditing=item.identity;managementEditName=item.displayName;managementEditIp=item.currentIp;managementEditProfile=profiles.some(profile=>profile.name===item.credentialProfile)?item.credentialProfile:'';managementEditCluster=item.clusterId?String(item.clusterId):'';}
  async function saveManagementEdit(item:Managed){const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({displayName:managementEditName,currentIp:managementEditIp,credentialProfile:managementEditProfile||undefined,clusterId:managementEditCluster?Number(managementEditCluster):null})}),value:any=await json(response);if(!response.ok){error=value.error??'无法保存 BMC 条目';return;}managementEditing='';await inventory();message='已更新本地 BMC 管理条目。';const updatedItem=managed.find(m=>m.identity.toLowerCase()===item.identity.toLowerCase());if(updatedItem) void probeManagement([updatedItem],true);}
  async function assignPickedManagedToCluster(){const selected=pickedManaged(),clusterId=Number(managementBatchCluster),cluster=clusters.find(item=>item.id===clusterId);if(!selected.length){error='请先勾选要加入集群的 BMC。';return;}if(!cluster){error='请选择目标集群。';return;}managementBusy=true;error='';try{const response=await fetch(`${base}/api/v1/managed-bmcs/batch/cluster`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({identities:selected.map(item=>item.identity),clusterId})}),value:any=await json(response);if(!response.ok)throw Error(value.error??'无法批量设置集群归属');managementPicked={...managementPicked,...Object.fromEntries(selected.map(item=>[item.identity,false]))};await inventory();message=`已将 ${value.updated} 台 BMC 加入集群 ${cluster.name}。`;}catch(reason){error=reason instanceof Error?reason.message:'无法批量设置集群归属';}finally{managementBusy=false;}}
  async function createCluster() { if(!clusterName.trim()){error='请填写集群名称。';return;} const response=await fetch(`${base}/api/v1/clusters`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:clusterName})}),value:any=await json(response);if(!response.ok){error=value.error??'无法创建集群';return;}clusterName='';await loadClusters();message=`已创建集群 ${value.name}。`; }
  function beginClusterEdit(cluster:Cluster){editingCluster=cluster.id;clusterEditName=cluster.name;}
  async function saveCluster(cluster:Cluster){const response=await fetch(`${base}/api/v1/clusters/${cluster.id}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({name:clusterEditName})}),value:any=await json(response);if(!response.ok){error=value.error??'无法更新集群';return;}editingCluster=undefined;await loadClusters();message=`已更新集群 ${value.name}。`;}
  async function removeCluster(cluster:Cluster){const count=clusterSize(cluster.id);if(!confirm(`删除集群 ${cluster.name}？${count?`其中 ${count} 台 BMC 会变为未分配集群，BMC 条目和历史不会删除。`:''}`))return;const response=await fetch(`${base}/api/v1/clusters/${cluster.id}`,{method:'DELETE'});if(!response.ok){error='无法删除集群';return;}if(managementClusterFilter===String(cluster.id))managementClusterFilter='all';await Promise.all([loadClusters(),inventory()]);message='已删除集群；成员 BMC 已保留为未分配状态。';}
  function setTarget(identity:string,value:string){targets={...targets,[identity]:value};} function choose(identity:string,value:boolean){picked={...picked,[identity]:value};}
  async function open(ip:string){try{if('__TAURI_INTERNALS__' in window)await openUrl(`https://${ip}`);else window.open(`https://${ip}`,'_blank')}catch{error='无法使用默认浏览器打开 BMC 地址'}}
  const label=(value:string)=>({online:'在线',offline:'离线',reachable:'可用',unreachable:'不可达',success:'成功',failed:'失败',unknown:'未检查',completed:'已完成',adopted_static:'已纳管·静态 IP',pending_reconfiguration:'待重新配置',manual:'手动记录',network_changed_unverified:'已变更，待验证'} as Record<string,string>)[value]??value;
</script>

<main>
  <header><div><h1>bmc-provisioner <button class="version" onclick={()=>showAbout=true}>v{currentVersion}</button></h1></div><span class="local">已连接</span></header>
  <nav aria-label="主导航"><button class:active={tab==='inventory'} onclick={()=>tab='inventory'}>BMC 清单 <span>{rows.length}</span></button><button class:active={tab==='management'} onclick={()=>tab='management'}>BMC 管理 <span>{managed.length}</span></button><button class:active={tab==='clusters'} onclick={()=>tab='clusters'}>集群 <span>{clusters.length}</span></button><button class:active={tab==='connection'} onclick={()=>tab='connection'}>连接设置</button><button class:active={tab==='profiles'} onclick={()=>tab='profiles'}>凭据档案 <span>{profiles.length}</span></button></nav>

  {#if tab==='inventory'}
    <section class="workspace"><div class="section-title"><div><h2>BMC 清单与访问状态</h2><p>来自 lessor 的动态发现与本地配置记录会按 MAC 合并；Relay 租约将在执行前由 Redfish 确认。</p></div><button onclick={refresh} disabled={loading||executing}>{loading?(progress||'刷新中…'):'刷新并检查状态'}</button></div>
    {#if rows.length}<div class="bmc-table"><div class="bmc-row table-heading"><span>选择 / BMC</span><span>MAC / 作用域</span><span>凭据档案</span><span>目标静态 IPv4 / 访问</span><span>状态</span></div>{#each rows as row}<div class:frozen={row.frozen} class="bmc-row"><label class="pick"><input type="checkbox" checked={picked[row.identity]} disabled={row.frozen||!row.candidate} onchange={event=>choose(row.identity,event.currentTarget.checked)}/><span><strong>{row.frozen?row.address:row.sourceIp}</strong><small>{row.frozen?`已冻结；来源 ${row.sourceIp}`:row.candidate?candidateLabel(row.candidate):'本地历史记录'}</small></span></label><span><code>{row.mac??'MAC 未返回'}</code><small>{row.scopeName}{row.subnet?` / ${row.subnet}/${row.prefix}`:''}</small></span><select value={profileByRow[row.identity]??''} onchange={event=>selectProfile(row,event.currentTarget.value)}><option value="">选择档案</option>{#each profiles as item}<option value={item.name}>{item.name} · {item.username}</option>{/each}</select><span>{#if row.managed&&editing===row.managed.identity}<input bind:value={editAddress}/><button onclick={()=>saveAddress(row.managed!)}>保存</button>{:else}<input value={targets[row.identity]??''} disabled={row.frozen||!row.candidate} oninput={event=>setTarget(row.identity,event.currentTarget.value)} placeholder="例如 172.16.40.200"/>{#if row.managed}<a href={`https://${row.address}`} onclick={event=>{event.preventDefault();void open(row.address)}}>https://{row.address}</a>{/if}{/if}</span>{#if row.managed}<span><strong>{label(row.managed.configurationStatus)}{row.frozen?' · 已冻结':''}</strong><small>{label(row.managed.onlineStatus)} / {label(row.managed.redfishStatus)} / {label(row.managed.authenticationStatus)}</small><span class="row-actions"><button onclick={()=>{editing=row.managed!.identity;editAddress=row.managed!.currentIp}}>编辑地址</button>{#if row.frozen}<button onclick={()=>reprovision(row.managed!)}>重新配置</button>{/if}<button class="text-danger" onclick={()=>remove(row.managed!)}>删除</button></span></span>{:else}<span><strong>待配置</strong><small>需先核验或执行配置</small></span>{/if}</div>{/each}</div><div class="batch-bar"><span>目标网络：/{targetPrefix}，网关 {targetGateway||'未设置'}</span><button class="secondary" onclick={inspectSelected} disabled={executing||inspecting}>{inspecting?(progress||'核验中…'):'核验并纳管已勾选 BMC'}</button><button class="danger" onclick={execute} disabled={executing||inspecting}>执行已勾选 BMC 的 IP 变更配置</button></div>{:else}<p class="muted">尚未读取到 BMC；请检查 lessor 连接设置。</p>{/if}
    <div class="manual-add"><strong>手动加入清单</strong><input bind:value={manualIp} placeholder="BMC IPv4，例如 172.16.40.200"/><input bind:value={manualMac} placeholder="MAC（可选）"/><select bind:value={manualProfile}><option value="">凭据档案（可选）</option>{#each profiles as item}<option value={item.name}>{item.name}</option>{/each}</select><button class="secondary" onclick={addManual}>加入清单</button></div></section>
  {:else if tab==='management'}
    <section class="workspace"><div class="section-title"><div><h2>BMC 管理</h2><p>本地清单是稳定数据源。按集群归类后，先刷新状态并确认首次证书，再执行电源操作。</p></div><button onclick={()=>refreshManagement()} disabled={managementBusy}>{managementBusy?(progress||'检查中…'):'刷新管理状态'}</button></div><div class="management-filter"><label>集群筛选<select bind:value={managementClusterFilter}><option value="all">全部集群</option><option value="unassigned">未分配集群</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}（{clusterSize(cluster.id)}）</option>{/each}</select></label><small>集群仅是本地管理归属，不会改变 lessor、DHCP 或 BMC 网络配置。</small></div>
    {#if filteredManaged().length}<div class="bmc-table management-table"><div class="bmc-row table-heading"><label class="pick select-all"><input type="checkbox" checked={allFilteredManagedPicked()} onchange={event=>chooseAllFilteredManaged(event.currentTarget.checked)}/><span>全选当前筛选结果</span></label><span>BMC / MAC</span><span>凭据档案</span><span>在线 / Redfish / 认证</span><span>电源状态 / 操作</span></div>{#each filteredManaged() as item}<div class="bmc-row"><label class="pick"><input type="checkbox" checked={managementPicked[item.identity]} onchange={event=>chooseManaged(item.identity,event.currentTarget.checked)}/><span><strong>{item.displayName||item.currentIp}</strong><small>{clusterLabel(item)} · {item.displayName?item.currentIp:'未命名服务器'}</small></span></label><span><a href={`https://${item.currentIp}`} onclick={event=>{event.preventDefault();void open(item.currentIp)}}>https://{item.currentIp}</a><small><code>{item.mac??'MAC 未设置'}</code> · {item.scopeName}</small></span>{#if managementEditing===item.identity}<span><select bind:value={managementEditProfile}><option value="">保持原档案</option>{#each profiles as profile}<option value={profile.name}>{profile.name} · {profile.username}</option>{/each}</select></span>{:else}<span><strong>{item.credentialProfile||'未选择'}</strong><small>凭据档案</small></span>{/if}<span><strong>{label(item.onlineStatus)} / {label(item.redfishStatus)} / {label(item.authenticationStatus)}</strong>{#if managementStatus[item.identity]?.certificateTrustRequired}<small>需确认 HTTPS 证书</small><button class="secondary compact" onclick={()=>trustManagementCertificate(item)}>信任证书并读取</button>{:else}<small>{managementStatus[item.identity]?.detail??(managementStatus[item.identity]?.power?'':'尚未刷新电源状态')}</small>{/if}</span><span>{#if managementEditing===item.identity}<div class="edit-management"><input bind:value={managementEditName} placeholder="服务器名称（可选）"/><input bind:value={managementEditIp} placeholder="BMC IPv4"/><select bind:value={managementEditCluster}><option value="">未分配集群</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}</option>{/each}</select><button class="secondary compact" onclick={()=>saveManagementEdit(item)}>保存</button><button class="compact" onclick={()=>managementEditing=''}>取消</button></div>{:else}<strong>{managementStatus[item.identity]?.power?.powerState??'未读取'}</strong><small>{managementStatus[item.identity]?.power?.systemUri??'刷新状态后显示 Redfish ComputerSystem'}</small><span class="row-actions"><button class="compact" title={powerHint(item,'on')} disabled={managementBusy||!supportsPower(item,'on')} onclick={()=>powerOne(item,'on')}>开机</button><button class="compact" title={powerHint(item,'shutdown')} disabled={managementBusy||!supportsPower(item,'shutdown')} onclick={()=>powerOne(item,'shutdown')}>关机</button><button class="compact" title={powerHint(item,'restart')} disabled={managementBusy||!supportsPower(item,'restart')} onclick={()=>powerOne(item,'restart')}>重启</button><button class="compact" onclick={()=>beginManagementEdit(item)}>编辑</button><button class="text-danger compact" onclick={()=>remove(item)}>删除</button></span>{/if}</span></div>{/each}</div><div class="batch-bar management-actions"><span><select bind:value={managementBatchCluster} aria-label="批量加入集群"><option value="">选择目标集群</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}</option>{/each}</select><button class="secondary" disabled={managementBusy||!managementBatchCluster} onclick={assignPickedManagedToCluster}>将已勾选 {pickedManaged().length} 台加入集群</button></span><span><button class="secondary" disabled={managementBusy} onclick={()=>executeManagementPower('on')}>批量开机</button><button class="danger" disabled={managementBusy} onclick={()=>executeManagementPower('shutdown')}>批量关机</button><button class="danger" disabled={managementBusy} onclick={()=>executeManagementPower('restart')}>批量重启</button></span></div>{:else}<p class="muted">当前筛选没有 BMC。可切换集群筛选，或直接手动加入。</p>{/if}
    <div class="management-add"><strong>手动加入 BMC</strong><input bind:value={managementAddName} placeholder="服务器名称（可选）"/><input bind:value={managementAddIp} placeholder="BMC IPv4，例如 172.16.40.18"/><input bind:value={managementAddMac} placeholder="MAC（可选）"/><select bind:value={managementAddCluster}><option value="">集群（可选）</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}</option>{/each}</select><select bind:value={managementAddProfile}><option value="">凭据档案（可选）</option>{#each profiles as profile}<option value={profile.name}>{profile.name} · {profile.username}</option>{/each}</select><button class="secondary" onclick={addManagementBmc}>加入管理</button></div></section>
  {:else if tab==='clusters'}
    <section class="workspace"><div class="section-title"><div><h2>集群</h2><p>集群仅保存名称，用于组织 BMC。BMC 条目保存集群归属，lessor 刷新不会覆盖它。</p></div></div><div class="cluster-create"><label>集群名称<input bind:value={clusterName} placeholder="例如 B300-训练集群-A"/></label><button class="primary" onclick={createCluster}>新建集群</button></div>{#if clusters.length}<div class="cluster-list">{#each clusters as cluster}<div class="cluster-row">{#if editingCluster===cluster.id}<div class="cluster-edit"><input bind:value={clusterEditName}/><button class="secondary" onclick={()=>saveCluster(cluster)}>保存</button><button onclick={()=>editingCluster=undefined}>取消</button></div>{:else}<span><strong>{cluster.name}</strong><small>{clusterSize(cluster.id)} 台 BMC</small></span><span class="row-actions"><button onclick={()=>{managementClusterFilter=String(cluster.id);tab='management'}}>查看 BMC</button><button onclick={()=>beginClusterEdit(cluster)}>编辑</button><button class="text-danger" onclick={()=>removeCluster(cluster)}>删除</button></span>{/if}</div>{/each}</div>{:else}<p class="muted">还没有集群。可按业务、机柜或任意名称创建集群。</p>{/if}</section>
  {:else if tab==='connection'}
    <section class="settings-page"><div class="section-title"><div><h2>连接设置</h2><p>lessor 是全局的 BMC 动态发现来源。批量写入默认最多同时处理 4 台；新地址验证不占用写入配额。</p></div></div><div class="setting-grid"><label>lessor 地址<input bind:value={lessorUrl} placeholder="http://127.0.0.1:8080"/></label><label>作用域 ID<input bind:value={scopeId} type="number" min="1"/></label></div><div class="setting-grid network"><label>默认 IPv4 前缀<input bind:value={targetPrefix} type="number" min="1" max="32"/></label><label>默认网关<input bind:value={targetGateway} placeholder="172.16.40.254"/></label><label>批量写入并发<select bind:value={batchConcurrency}><option value={1}>1 台（串行）</option><option value={2}>2 台</option><option value={4}>4 台（默认）</option><option value={8}>8 台</option></select></label><label>状态自动探测间隔<select value={probeIntervalSecs} onchange={event=>setProbeInterval(Number(event.currentTarget.value))}><option value={0}>关闭自动探测</option><option value={15}>15 秒</option><option value={30}>30 秒（默认）</option><option value={60}>60 秒</option><option value={120}>120 秒（2分钟）</option></select></label></div><button class="primary" onclick={saveConnection} disabled={savingConnection}>{savingConnection?'保存中…':'保存连接设置'}</button></section>
  {:else}
    <section class="settings-page"><div class="section-title"><div><h2>凭据档案</h2><p>档案名称和用户名保存到本机数据目录；桌面端密码仅保存到 Windows 凭据管理器。Docker 使用当前服务会话，服务重启后需要重新填写密码。</p></div></div><div class="profile-form"><label>档案名称<input bind:value={profileName} placeholder="例如 default、rack-a"/></label><label>用户名<input bind:value={profileUsername} placeholder="root"/></label><label>当前密码<input bind:value={profileCurrentPassword} type="password"/></label><label>新密码 <small>首次强制改密时使用</small><input bind:value={profileNewPassword} type="password"/></label><button class="primary" onclick={saveProfile}>保存档案</button></div><div class="profile-recovery"><span><strong>恢复已有 Windows 档案</strong><small>升级前的密码仍在凭据管理器时，输入原档案名即可恢复其名称和用户名；不会显示、导出或改写密码。</small></span><input bind:value={restoreProfileName} placeholder="例如 asrr-default" onkeydown={event=>{if(event.key==='Enter')void restoreProfile()}}/><button class="secondary" onclick={restoreProfile}>恢复档案</button></div>{#if profiles.length}<div class="profile-list">{#each profiles as item}<div><span><strong>{item.name}</strong><small>{item.username} · 系统凭据管理器或当前服务会话</small></span><button class="text-danger" onclick={()=>removeProfile(item.name)}>删除</button></div>{/each}</div>{:else}<p class="muted">还没有凭据档案。先创建一个档案，或恢复已有的 Windows 档案，再回到 BMC 清单逐行选择。</p>{/if}</section>
  {/if}
  {#if executionLogs.length}<section class="execution-log" aria-live="polite"><div><h2>执行日志</h2><small>{executing ? '任务执行中，日志会持续更新' : '本次任务已结束'}</small></div><ol>{#each executionLogs as item}<li><time>{timestamp(item.timestampMs)}</time><span>{item.message}</span></li>{/each}</ol></section>{/if}
  <footer aria-live="polite">{#if error}<p class="error">{error}</p>{/if}<p>{message}</p></footer>
  {#if showAbout}<UpdateDialog version={currentVersion} onclose={()=>showAbout=false}/>{/if}
</main>
