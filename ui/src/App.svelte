<script lang="ts">
  import { onMount, onDestroy } from 'svelte';
  import { openUrl } from '@tauri-apps/plugin-opener';
  import UpdateDialog from './lib/UpdateDialog.svelte';
  import PowerControls from './lib/PowerControls.svelte';
  import GpuPanel from './lib/GpuPanel.svelte';
  import HardwarePanel from './lib/HardwarePanel.svelte';
  import type { GpuTelemetry, HardwareTelemetry } from './lib/telemetry';
  import { powerActionNames, powerDescriptions, isForcedPowerAction, isPowerOffAction, type PowerAction } from './lib/power';
  import { desktopVersion } from './lib/desktop';

  // The desktop WebView origin is a Tauri-owned asset origin, not bmc-provisionerd.
  // Both the packaged desktop app and Vite development UI therefore use the local API
  // service explicitly.  Using window.location.origin here makes a packaged build fetch
  // its own HTML fallback and later try to iterate an object as the BMC candidate list.
  const base = 'http://127.0.0.1:6770';
  type Candidate = { scopeId:number; scopeName:string; subnet:string; prefix:number; ip:string; mac?:string; source:'confirmedDiscovery'|'relayDhcpLease' };
  type Managed = { identity:string; displayName:string; clusterId?:number; mac?:string; bmcMac?:string; serialNumber?:string; hardwareModel?:string; scopeId:number; scopeName:string; sourceIp:string; currentIp:string; credentialProfile:string; credentialUsername?:string; credentialUpdatedAt?:number; configurationStatus:string; onlineStatus:string; redfishStatus:string; authenticationStatus:string; lastCheckedAt?:number };
  type Profile = { name:string; username:string };
  type Cluster = { id:number; name:string; createdAt:number };
  type JobLog = { timestampMs:number; message:string };
  type PowerStatus = { systemUri:string; powerState?:string; supportedActions:PowerAction[] };
  type ManagedPowerStatus = { managed:Managed; power?:PowerStatus; detail?:string };
  type PendingPowerTransition = { action:PowerAction; startedAt:number };
  type Telemetry = {
    systemUri:string; name?:string; manufacturer?:string; model?:string; serialNumber?:string;
    powerState?:string; health?:string; powerWatts?:number; temperatureCelsius?:number;
    cpu:{packages:number;cores?:number;threads?:number;model?:string;health?:string};
    memory:{modules:number;capacityMib?:number;health?:string};
    storage:{drives:number;capacityBytes?:number;health?:string};
    gpu?:GpuTelemetry; hardware?:HardwareTelemetry;
  };
  type ManagedTelemetry = { managed:Managed; telemetry?:Telemetry; detail?:string };
  type TelemetryCache = { telemetry?:Telemetry; detail?:string; collectedAt:number };
  type TelemetryMetric = 'powerWatts'|'temperatureCelsius';
  type TelemetryHistoryPoint = { collectedAt:number; powerWatts?:number; temperatureCelsius?:number };
  type TelemetryHistory = { points:TelemetryHistoryPoint[]; startAt:number; endAt:number; bucketSeconds:number };
  type TelemetryRange = 3600|21600|86400|604800|2592000|7776000|31536000;
  type Row = { identity:string; candidate?:Candidate; managed?:Managed; sourceIp:string; address:string; mac?:string; scopeName:string; subnet?:string; prefix?:number; frozen:boolean };

  let tab = $state<'overview'|'inventory'|'connection'|'profiles'|'management'|'clusters'|'detail'>('overview');
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
  let message = $state('BMC Fleet 本地控制台已就绪。');
  let error = $state('');
  let progress = $state('');
  let executionLogs = $state<JobLog[]>([]);
  let showAbout = $state(false);
  let currentVersion = $state('…');
  let managementPicked = $state<Record<string,boolean>>({});
  let managementStatus = $state<Record<string,ManagedPowerStatus>>({});
  let pendingPowerTransitions = $state<Record<string,PendingPowerTransition>>({});
  let managementBusy = $state(false);
  let managementAddName = $state('');
  let managementAddIp = $state('');
  let managementAddMac = $state('');
  let managementAddUsername = $state('');
  let managementAddPassword = $state('');
  let managementAddDialog: HTMLDialogElement;
  let managementAdding = $state(false);
  let managementAddError = $state('');
  let managementEditing = $state('');
  let managementEditName = $state('');
  let managementEditIp = $state('');
  let managementEditUsername = $state('');
  let managementEditPassword = $state('');
  let managementClusterFilter = $state('all');
  let managementAddCluster = $state('');
  let managementEditCluster = $state('');
  let clusterName = $state('');
  let clusterCreating = $state(false);
  let editingCluster = $state<number|undefined>();
  let clusterEditName = $state('');
  let probeIntervalSecs = $state(30);
  let probeTimer: ReturnType<typeof setInterval> | null = null;
  let probing = false;
  let managementSearch = $state('');
  let activeMachine = $state<Managed|undefined>();
  let telemetry = $state<Telemetry|undefined>();
  let telemetryLoading = $state(false);
  let telemetryError = $state('');
  let telemetryByIdentity = $state<Record<string,TelemetryCache>>({});
  let telemetryCollecting = false;
  let telemetryHistory = $state<TelemetryHistory|undefined>();
  let telemetryHistoryLoading = $state(false);
  let telemetryHistoryError = $state('');
  let telemetryRange = $state<TelemetryRange>(86400);
  const POWER_TRANSITION_SETTLE_MS = 20_000;
  const POWER_TRANSITION_TIMEOUT_MS = 180_000;
  const POWER_TRANSITION_POLL_MS = 3_000;

  // Candidate discovery is intentionally scoped to the Lessor initialization view.
  // Do not carry a failed Lessor discovery message into the independent fleet views,
  // where it misleadingly suggests that clusters or Redfish management use Lessor.
  function isLessorCandidateError(value: string) {
    const normalized = value.trim().toLowerCase();
    return normalized.includes('lessor') && (normalized.includes('candidate') || normalized.includes('候选'));
  }
  $effect(() => {
    if (tab !== 'inventory' && isLessorCandidateError(error)) error = '';
  });

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
          void probeManagement(undefined, true);
          void collectTelemetry();
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
    // BMC Fleet is an independent control plane: opening the desktop application must
    // never contact Lessor.  The Lessor workspace explicitly opts into discovery below.
    await Promise.all([inventory(), loadProfiles(), loadClusters()]);
    if (managed.length > 0) {
      void probeManagement(undefined, true);
      void collectTelemetry();
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
  async function refreshProvisioning() {
    loading=true; error='';
    try {
      // This is the only UI workflow that asks Lessor for candidates.  Local inventory and
      // credential profiles are read only to render the provisioning context.
      await Promise.all([load(), inventory(), loadProfiles()]);
      message = candidates.length ? `已从 Lessor 读取 ${candidates.length} 台待配置 BMC。` : 'Lessor 当前没有返回待配置 BMC。';
    } catch(reason) { error=reason instanceof Error ? reason.message : '无法读取 Lessor BMC 列表'; }
    finally { loading=false; progress=''; }
  }
  function openProvisioning() { tab='inventory'; void refreshProvisioning(); }
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
  async function saveProfile() { if(!profileName || !profileUsername || !profileCurrentPassword){error='请填写初始化档案名称、用户名和当前密码。';return;} const response=await fetch(`${base}/api/v1/credential-profiles`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name:profileName,username:profileUsername,currentPassword:profileCurrentPassword,newPassword:profileNewPassword})});if(!response.ok){error='无法保存初始化凭据';return;}profileName='';profileUsername='';profileCurrentPassword='';profileNewPassword='';await loadProfiles();message='已保存 Lessor 批量初始化凭据。'; }
  async function restoreProfile() { if(!restoreProfileName.trim()){error='请输入需要恢复的档案名称。';return;} error=''; const name=restoreProfileName.trim(), response=await fetch(`${base}/api/v1/credential-profiles/${encodeURIComponent(name)}/restore`,{method:'POST'}), value=await json(response); if(!response.ok){error=value.error??'没有找到对应的系统凭据档案。';return;} restoreProfileName='';await loadProfiles();message=`已恢复凭据档案 ${value.name}；密码未显示、导出或改写。`; }
  async function removeProfile(name:string) { if(!confirm(`删除凭据档案 ${name}？已关联的 BMC 将不能再自动检查或配置。`))return;const response=await fetch(`${base}/api/v1/credential-profiles/${encodeURIComponent(name)}`,{method:'DELETE'});if(!response.ok){error='无法删除凭据档案';return;}await loadProfiles();message='已删除凭据档案。'; }
  function chooseManaged(identity:string,value:boolean){managementPicked={...managementPicked,[identity]:value};}
  function clusterFor(item:Managed) { return clusters.find(cluster=>cluster.id===item.clusterId); }
  function clusterLabel(item:Managed) { return clusterFor(item)?.name ?? '未分配集群'; }
  function hasManagedCredential(item:Managed) { return Boolean(item.credentialUsername || item.credentialProfile); }
  function managedCredentialLabel(item:Managed) { return item.credentialUsername ? `${item.credentialUsername} · 已保存` : item.credentialProfile ? '旧档案 · 待迁移' : '未设置'; }
  function managedCredentialHint(item:Managed) { return item.credentialUsername ? `登录用户名 ${item.credentialUsername}；密码已加密保存到本地数据库` : item.credentialProfile ? '该 BMC 正在兼容使用旧凭据档案；编辑后保存账号和密码即可迁移' : '编辑此 BMC，保存账号和密码后开始自动采集'; }
  type ManagedReadiness = 'ready'|'attention'|'pending';
  function managedReadiness(item:Managed):ManagedReadiness {
    if (['offline','failed','unreachable'].includes(item.onlineStatus) || ['failed','unreachable'].includes(item.redfishStatus) || item.authenticationStatus==='failed') return 'attention';
    if (item.onlineStatus==='online' && item.redfishStatus==='reachable' && item.authenticationStatus==='success') return 'ready';
    if (!hasManagedCredential(item) || item.onlineStatus==='unknown' || item.redfishStatus==='unknown' || item.authenticationStatus==='unknown') return 'pending';
    return 'attention';
  }
  function managedReadinessLabel(item:Managed) {
    if (managedReadiness(item)==='ready') return 'BMC 在线';
    if (!hasManagedCredential(item)) return '缺少登录凭据';
    if (item.onlineStatus==='offline' || item.onlineStatus==='unreachable') return 'BMC 不可达';
    if (item.redfishStatus==='failed' || item.redfishStatus==='unreachable') return 'Redfish 不可用';
    if (item.authenticationStatus==='failed') return '认证失败';
    return '等待检查';
  }
  function managedReadinessHint(item:Managed) {
    if (managedReadiness(item)==='ready') return '全部就绪：BMC 在线、Redfish 可用且登录凭据已验证';
    return managementStatus[item.identity]?.detail ?? managedReadinessLabel(item);
  }
  function clusterSize(clusterId:number) { return managed.filter(item=>item.clusterId===clusterId).length; }
  function filteredManaged() {
    const clusterItems = managementClusterFilter==='all' ? managed : managementClusterFilter==='unassigned' ? managed.filter(item=>!item.clusterId) : managed.filter(item=>item.clusterId===Number(managementClusterFilter));
    const query = managementSearch.trim().toLowerCase();
    return query ? clusterItems.filter(item => [item.displayName, item.currentIp, item.bmcMac, item.serialNumber, item.hardwareModel, item.mac, item.scopeName, clusterLabel(item)].some(value => value?.toLowerCase().includes(query))) : clusterItems;
  }
  function allFilteredManagedPicked() { const visible=filteredManaged(); return visible.length>0 && visible.every(item=>managementPicked[item.identity]); }
  function chooseAllFilteredManaged(value:boolean) { managementPicked={...managementPicked,...Object.fromEntries(filteredManaged().map(item=>[item.identity,value]))}; }
  function pickedManaged() { return managed.filter(item=>managementPicked[item.identity]); }
  async function managementStatusOne(item:Managed) {
    const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/power/status`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'});
    const value:any=await json(response);
    if(!response.ok) throw Error(value.error??'无法读取 BMC 管理状态');
    managementStatus={...managementStatus,[item.identity]:value as ManagedPowerStatus};
    reconcilePowerTransition(item, value as ManagedPowerStatus);
  }
  async function probeManagement(only?:Managed[], silent=false) {
    const items=(only??managed).filter(item=>!isDraft(item)&&hasManagedCredential(item));
    if(!items.length){
      if(!silent) message=managed.length?'请先编辑 BMC 并保存登录用户名和密码，系统会自动检查状态。':'还没有本地 BMC 清单；可先手动加入，或从 lessor 发现后执行配置。';
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
          managementStatus={...managementStatus,[item.identity]:{managed:item,detail}};
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
  function pendingPowerTransition(item:Managed) { return pendingPowerTransitions[item.identity]; }
  function serverPowerView(item:Managed) {
    const pending=pendingPowerTransition(item);
    if(pending) return {tone:'changing', label:powerTransitionLabel(pending.action), hint:powerTransitionHint(pending.action)};
    const status=managementStatus[item.identity];
    if(managedReadiness(item)!=='ready' || !status?.power) return {tone:'unknown', label:'未知', hint:'尚未获取当前服务器电源状态'};
    switch(status.power.powerState?.toLowerCase()) {
      case 'on': return {tone:'on', label:'已开机', hint:'服务器电源已开启'};
      case 'off': return {tone:'off', label:'已关机', hint:'服务器电源已关闭，BMC 仍可在线管理'};
      case 'poweringon': return {tone:'changing', label:'开机中', hint:'服务器正在开启电源'};
      case 'poweringoff': return {tone:'changing', label:'关机中', hint:'服务器正在关闭电源'};
      case 'paused': return {tone:'off', label:'已暂停', hint:'服务器执行已暂停'};
      default: return {tone:'unknown', label:'未知', hint:'设备未返回可识别的电源状态'};
    }
  }
  function powerTransitionLabel(action:PowerAction) { return `正在${powerActionNames[action]}…`; }
  function powerTransitionHint(action:PowerAction) { return isPowerOffAction(action) ? '命令已提交，等待服务器关闭电源' : '命令已提交，等待确认服务器电源状态'; }
  function clearPowerTransition(identity:string) {
    const { [identity]: _removed, ...remaining } = pendingPowerTransitions;
    pendingPowerTransitions = remaining;
  }
  function transitionReachedTarget(transition:PendingPowerTransition, status?:PowerStatus) {
    const state=status?.powerState?.toLowerCase();
    if (transition.action==='on') return state==='on';
    if (isPowerOffAction(transition.action)) return state==='off';
    return Date.now()-transition.startedAt>=POWER_TRANSITION_SETTLE_MS && state==='on';
  }
  function reconcilePowerTransition(item:Managed, status:ManagedPowerStatus) {
    const transition=pendingPowerTransition(item);
    if (!transition) return;
    if (transitionReachedTarget(transition,status.power)) clearPowerTransition(item.identity);
  }
  function schedulePowerTransitionCheck(item:Managed) {
    setTimeout(async()=>{
      const transition=pendingPowerTransition(item);
      if (!transition) return;
      if (Date.now()-transition.startedAt>=POWER_TRANSITION_TIMEOUT_MS) {
        clearPowerTransition(item.identity);
        const previous=managementStatus[item.identity];
        managementStatus={...managementStatus,[item.identity]:{managed:previous?.managed??item,power:previous?.power,detail:`${powerActionNames[transition.action]}命令已提交，但 3 分钟内未确认到最终状态`}};
        return;
      }
      try { await managementStatusOne(item); } catch { /* Keep the action locked until a later poll or timeout. */ }
      if (pendingPowerTransition(item)) schedulePowerTransitionCheck(item);
    },POWER_TRANSITION_POLL_MS);
  }
  function beginPowerTransition(item:Managed, updated:Managed, action:PowerAction, resetType:string) {
    pendingPowerTransitions={...pendingPowerTransitions,[item.identity]:{action,startedAt:Date.now()}};
    const previous=managementStatus[item.identity];
    managementStatus={...managementStatus,[item.identity]:{managed:updated,power:previous?.power,detail:`已提交${powerActionNames[action]}（${resetType}）`}};
    schedulePowerTransitionCheck(item);
  }
  function supportsPower(item:Managed,action:PowerAction) {
    if (pendingPowerTransition(item)) return false;
    const status = managementStatus[item.identity];
    if (!status?.power?.supportedActions.includes(action)) return false;

    // 根据当前电源状态智能禁用不适用的操作
    const powerState = status.power.powerState?.toLowerCase();
    if (action === 'on' && powerState === 'on') return false;  // 已开机，禁用开机按钮
    if (action !== 'on' && powerState === 'off') return false;
    if (powerState === 'poweringon' || powerState === 'poweringoff') return false;

    return true;
  }
  // Explains a disabled power button instead of leaving the operator to guess.
  function powerHint(item:Managed,action:PowerAction) {
    const transition=pendingPowerTransition(item);
    if (transition) return powerTransitionHint(transition.action);
    if(supportsPower(item,action)) return powerDescriptions[action];
    const status=managementStatus[item.identity];
    if(!status) return probeIntervalSecs===0?'自动采集已暂停，请先恢复自动采集':'等待自动采集设备状态';
    if(!status.power) return status.detail??'未能读取 Redfish 电源状态';
    const powerState=status.power.powerState?.toLowerCase();
    if(action==='on'&&powerState==='on') return 'BMC 当前已开机';
    if(action!=='on'&&powerState==='off') return '服务器当前已关机';
    if(powerState==='poweringon'||powerState==='poweringoff') return '服务器正在切换电源状态';
    return `该设备未声明支持${powerActionNames[action]}`;
  }
  // Acts on the clicked row only. The batch bar keeps using executeManagementPower.
  async function powerOne(item:Managed,action:PowerAction) {
    if(managementBusy || !supportsPower(item,action)) return;
    if(!confirm(`${isForcedPowerAction(action)?'高风险操作：':''}确认对 ${item.displayName||item.currentIp} 执行${powerActionNames[action]}？\n${powerDescriptions[action]}`)) return;
    managementBusy=true; error='';
    try {
      const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/power`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action})}),value:any=await json(response);
      if(!response.ok) throw Error(value.error??'操作失败');
      beginPowerTransition(item,value.managed,action,value.command.resetType);
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
    if(managementBusy) return;
    const selected=managed.filter(item=>managementPicked[item.identity]);
    if(!selected.length){error='请至少勾选一台 BMC。';return;}
    const eligible=selected.filter(item=>supportsPower(item,action));
    if(!eligible.length){error='所选 BMC 尚未完成状态探测，或其 Redfish 未声明支持此操作。';return;}
    const names=powerActionNames;
    const targets=eligible.map(item=>`${item.displayName||item.currentIp} (${item.currentIp})`).join('\n');
    if(!confirm(`${isForcedPowerAction(action)?'高风险批量操作：':''}确认对 ${eligible.length} 台服务器执行${names[action]}？\n${powerDescriptions[action]}\n${selected.length-eligible.length ? `跳过 ${selected.length-eligible.length} 台不支持或正在处理的设备。\n` : ''}${targets}`)) return;
    if(isForcedPowerAction(action) && prompt(`此次操作会中断 ${eligible.length} 台服务器上的业务，未保存的数据可能丢失。\n请输入“${names[action]}”确认执行。`) !== names[action]) return;
    managementBusy=true; error=''; const failed:string[]=[];
    try { await runWithLimit(eligible,Math.min(batchConcurrency,4),async(item,index)=>{progress=`${names[action]} ${index+1}/${eligible.length}：${item.currentIp}`;const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/power`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({action})}),value:any=await json(response);if(!response.ok){failed.push(`${item.currentIp}：${value.error??'操作失败'}`);return;}beginPowerTransition(item,value.managed,action,value.command.resetType);}); await inventory(); message=`批量${names[action]}已提交：成功 ${eligible.length-failed.length} 台，失败 ${failed.length} 台。`;if(failed.length)error=failed.join('；'); } finally {managementBusy=false;progress='';setTimeout(()=>{if(eligible.length)void probeManagement(eligible,true);},2500);}
  }
  function resetManagementAdd() {
    managementAddName=''; managementAddIp=''; managementAddMac='';
    managementAddUsername=''; managementAddPassword=''; managementAddCluster=''; managementAddError='';
  }
  function openManagementAdd() {
    resetManagementAdd();
    managementAddCluster=clusters.some(cluster=>String(cluster.id)===managementClusterFilter)?managementClusterFilter:'';
    managementAddDialog.showModal();
    managementAddDialog.querySelector<HTMLInputElement>('input')?.focus();
  }
  async function addManagementBmc() {
    if(managementAdding) return;
    managementAddError='';
    const ip=managementAddIp.trim(), username=managementAddUsername.trim();
    if(!/^(\d{1,3}\.){3}\d{1,3}$/.test(ip)||ip.split('.').some(part=>Number(part)>255)) { managementAddError='请填写有效的 BMC IPv4 地址。'; return; }
    if(Boolean(username)!==Boolean(managementAddPassword)){managementAddError='请同时填写用户名和密码，或将两项都留空。';return;}
    managementAdding=true;
    try {
      const response=await fetch(`${base}/api/v1/managed-bmcs`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({currentIp:ip,mac:managementAddMac.trim()||undefined,scopeName:'BMC 管理',displayName:managementAddName.trim()||undefined,credentialUsername:username||undefined,credentialPassword:managementAddPassword||undefined})}), value:any=await json(response);
      if(!response.ok) throw Error(value.error??'无法新建 BMC');
      const cluster=managementAddCluster;
      let clusterSaved=true;
      if(cluster) {
        try {
          const updated=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(value.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({clusterId:Number(cluster)})});
          clusterSaved=updated.ok;
        } catch { clusterSaved=false; }
      }
      // The BMC is already persisted: close the form even if assigning its cluster failed.
      managementAddDialog.close(); resetManagementAdd(); managementSearch='';
      managementClusterFilter=cluster&&clusterSaved?cluster:'unassigned';
      error=clusterSaved?'':'BMC 已创建，但集群归属未保存，可在设备编辑中重新选择集群。';
      message=`已新建 BMC：${value.displayName||ip}。`;
      try {
        await inventory();
        const newItem=managed.find(item=>item.identity.toLowerCase()===value.identity.toLowerCase());
        if(newItem) void probeManagement([newItem],true);
      } catch { error='BMC 已创建，清单刷新失败，请刷新后查看。'; }
    } catch(reason) {
      managementAddError=reason instanceof TypeError?'本地服务未连接，请稍后重试。':reason instanceof Error?reason.message:'无法新建 BMC';
    } finally { managementAdding=false; }
  }
  function isDraft(item:Managed){return item.configurationStatus==='draft';}
  function beginManagementEdit(item:Managed){managementEditing=item.identity;managementEditName=item.displayName;managementEditIp=item.currentIp;managementEditUsername=item.credentialUsername??'';managementEditPassword='';managementEditCluster=item.clusterId?String(item.clusterId):'';}
  async function duplicateManagementBmc(item:Managed){managementBusy=true;error='';try{const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/duplicate`,{method:'POST'}),value:any=await json(response);if(!response.ok)throw Error(value.error??'无法复制 BMC 条目');managementSearch='';await inventory();const copied=managed.find(candidate=>candidate.identity===value.identity);if(!copied)throw Error('复制条目未返回本地清单');beginManagementEdit(copied);message=`已创建 ${copied.displayName}；BMC IPv4 已复制，可直接修改后保存确认。`;}catch(reason){error=reason instanceof Error?reason.message:'无法复制 BMC 条目';}finally{managementBusy=false;}}
  async function saveManagementEdit(item:Managed){if(isDraft(item)&&!managementEditIp.trim()){error='复制的 BMC 条目需要填写新的 BMC IPv4。';return;}if(managementEditPassword&&!managementEditUsername.trim()){error='设置新密码时请填写 BMC 用户名。';return;}const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({displayName:managementEditName,currentIp:managementEditIp,clusterId:managementEditCluster?Number(managementEditCluster):null,deviceCredentials:managementEditPassword?{username:managementEditUsername.trim(),password:managementEditPassword}:undefined})}),value:any=await json(response);if(!response.ok){error=value.error??'无法保存 BMC 条目';return;}managementEditing='';await inventory();message=managementEditPassword?'已更新 BMC 条目并加密保存登录凭据。':'已更新本地 BMC 管理条目。';const updatedItem=managed.find(m=>m.identity.toLowerCase()===item.identity.toLowerCase());if(updatedItem) void probeManagement([updatedItem],true);}
  async function createCluster() {
    const name=clusterName.trim();
    if(!name){error='请填写集群名称。';return;}
    clusterCreating=true; error='';
    try {
      const response=await fetch(`${base}/api/v1/clusters`,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({name})}),value:any=await json(response);
      if(!response.ok){error=value.error??'无法创建集群';return;}
      clusterName=''; await loadClusters(); message=`已创建集群 ${value.name}。`;
    } catch {
      error='本地控制面未连接，无法创建集群。请确认桌面端服务已启动。';
    } finally { clusterCreating=false; }
  }
  function beginClusterEdit(cluster:Cluster){editingCluster=cluster.id;clusterEditName=cluster.name;}
  async function saveCluster(cluster:Cluster){const response=await fetch(`${base}/api/v1/clusters/${cluster.id}`,{method:'PATCH',headers:{'content-type':'application/json'},body:JSON.stringify({name:clusterEditName})}),value:any=await json(response);if(!response.ok){error=value.error??'无法更新集群';return;}editingCluster=undefined;await loadClusters();message=`已更新集群 ${value.name}。`;}
  async function removeCluster(cluster:Cluster){const count=clusterSize(cluster.id);if(!confirm(`删除集群 ${cluster.name}？${count?`其中 ${count} 台 BMC 会变为未分配集群，BMC 条目和历史不会删除。`:''}`))return;const response=await fetch(`${base}/api/v1/clusters/${cluster.id}`,{method:'DELETE'});if(!response.ok){error='无法删除集群';return;}if(managementClusterFilter===String(cluster.id))managementClusterFilter='all';await Promise.all([loadClusters(),inventory()]);message='已删除集群；成员 BMC 已保留为未分配状态。';}
  function totalOnline() { return managed.filter(item => item.onlineStatus === 'online').length; }
  function attentionCount() { return managed.filter(item => ['offline','failed','unreachable'].includes(item.onlineStatus) || ['failed','unreachable'].includes(item.redfishStatus) || item.authenticationStatus === 'failed').length; }
  function clusterHealth(cluster:Cluster) {
    const members = managed.filter(item => item.clusterId === cluster.id);
    if (!members.length) return 'empty';
    if (members.some(item => ['offline','failed','unreachable'].includes(item.onlineStatus) || ['failed','unreachable'].includes(item.redfishStatus) || item.authenticationStatus === 'failed')) return 'attention';
    if (members.every(item => item.onlineStatus === 'online' && item.redfishStatus === 'reachable')) return 'healthy';
    return 'pending';
  }
  function clusterHealthLabel(cluster:Cluster) {
    return ({ healthy:'稳定', attention:'需处理', pending:'待检查', empty:'空集群' } as Record<string,string>)[clusterHealth(cluster)];
  }
  function clusterOnlineCount(cluster:Cluster) { return managed.filter(item => item.clusterId === cluster.id && item.onlineStatus === 'online').length; }
  function clusterAttentionCount(cluster:Cluster) {
    return managed.filter(item => item.clusterId === cluster.id && (
      ['offline','failed','unreachable'].includes(item.onlineStatus)
      || ['failed','unreachable'].includes(item.redfishStatus)
      || item.authenticationStatus === 'failed'
    )).length;
  }
  function clusterLastChecked(cluster:Cluster) {
    const timestamps = managed.filter(item => item.clusterId === cluster.id)
      .map(item => item.lastCheckedAt)
      .filter((timestamp): timestamp is number => typeof timestamp === 'number' && Number.isFinite(timestamp));
    return timestamps.length ? `最近检查 ${new Date(Math.max(...timestamps)).toLocaleTimeString('zh-CN',{hour12:false})}` : '等待首次状态检查';
  }
  function openCluster(cluster:Cluster) { managementClusterFilter=String(cluster.id); managementSearch=''; tab='management'; }
  function isMetric(value:unknown): value is number { return typeof value==='number' && Number.isFinite(value); }
  function formatWatts(value?:number|null) { return isMetric(value) ? `${Math.round(value).toLocaleString('zh-CN')} W` : '未提供'; }
  function formatTemperature(value?:number|null) { return isMetric(value) ? `${value.toFixed(1)} °C` : '未提供'; }
  function formatMemory(value?:number|null) { return !isMetric(value) ? '未提供' : value >= 1024 ? `${(value / 1024).toFixed(value % 1024 ? 1 : 0)} GiB` : `${value} MiB`; }
  function formatStorage(value?:number|null) { if (!isMetric(value)) return '未提供'; const tebibytes = value / 1024 ** 4; return tebibytes >= 1 ? `${tebibytes.toFixed(1)} TiB` : `${(value / 1024 ** 3).toFixed(0)} GiB`; }
  function monitoringFailure(reason:unknown) {
    if(reason instanceof TypeError && /fetch/i.test(reason.message)) return '本地监控服务未连接；后台会在下个采集周期重试。';
    return reason instanceof Error ? reason.message : '自动采集 Redfish 监控数据失败。';
  }
  function applyTelemetry(item:Managed, value:ManagedTelemetry) {
    const cache:TelemetryCache={
      telemetry:value.telemetry,
      detail:value.detail,
      collectedAt:Date.now(),
    };
    telemetryByIdentity={...telemetryByIdentity,[item.identity]:cache};
    if(value.managed) managed=managed.map(existing=>existing.identity===value.managed.identity?value.managed:existing);
    if(activeMachine?.identity===item.identity) {
      showCachedTelemetry(item, cache);
      void loadTelemetryHistory(item);
    }
  }
  function showCachedTelemetry(item:Managed, cache?:TelemetryCache) {
    telemetry=cache?.telemetry;
    telemetryError=cache?.detail??(cache ? '该 BMC 未提供可用的标准监控资源。' : '正在等待后台采集此设备的监控数据。');
    telemetryLoading=!cache;
    activeMachine=item;
  }
  async function requestTelemetry(item:Managed) {
    const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/telemetry`,{method:'POST',headers:{'content-type':'application/json'},body:'{}'}), value:any=await json(response);
    if(!response.ok) throw Error(value.error??'无法读取 Redfish 监控数据');
    return value as ManagedTelemetry;
  }
  async function collectTelemetry(only?:Managed[]) {
    const items=(only??managed).filter(item=>!isDraft(item)&&hasManagedCredential(item));
    if(!items.length || telemetryCollecting) return;
    telemetryCollecting=true;
    try {
      await runWithLimit(items,Math.min(batchConcurrency,2),async(item)=>{
        try { applyTelemetry(item,await requestTelemetry(item)); }
        catch(reason) {
          const cache:TelemetryCache={detail:monitoringFailure(reason),collectedAt:Date.now()};
          telemetryByIdentity={...telemetryByIdentity,[item.identity]:cache};
          if(activeMachine?.identity===item.identity) showCachedTelemetry(item,cache);
        }
      });
    } finally { telemetryCollecting=false; }
  }
  function openMachine(item:Managed) {
    telemetryHistory=undefined;
    telemetryHistoryError='';
    if(isDraft(item)) {
      showCachedTelemetry(item,{detail:'请先确认或修改该条目的 BMC IPv4 并保存；保存后会自动开始采集。',collectedAt:Date.now()});
      return;
    }
    if(!hasManagedCredential(item)) {
      showCachedTelemetry(item,{detail:'此 BMC 尚未保存登录凭据，后台无法采集 Redfish 监控数据。',collectedAt:Date.now()});
    } else {
      showCachedTelemetry(item,telemetryByIdentity[item.identity]);
    }
    void loadTelemetryHistory(item);
  }
  function telemetryUpdatedAt(item:Managed) {
    const timestamp=telemetryByIdentity[item.identity]?.collectedAt;
    return timestamp ? new Date(timestamp).toLocaleTimeString('zh-CN',{hour12:false}) : '等待首次采集';
  }
  async function loadTelemetryHistory(item:Managed) {
    telemetryHistoryLoading=true;
    telemetryHistoryError='';
    try {
      const response=await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/telemetry/history?rangeSeconds=${telemetryRange}`), value:any=await json(response);
      if(!response.ok) throw Error(value.error??'无法读取本地监控历史');
      if(!Array.isArray(value.points)) throw Error('本地监控历史格式无效');
      if(activeMachine?.identity===item.identity) telemetryHistory=value as TelemetryHistory;
    } catch(reason) {
      if(activeMachine?.identity===item.identity) telemetryHistoryError=reason instanceof Error?reason.message:'无法读取本地监控历史';
    } finally {
      if(activeMachine?.identity===item.identity) telemetryHistoryLoading=false;
    }
  }
  function setTelemetryRange(value:number) {
    telemetryRange=value as TelemetryRange;
    if(activeMachine) void loadTelemetryHistory(activeMachine);
  }
  function historyMetricPoints(metric:TelemetryMetric) {
    return (telemetryHistory?.points??[]).flatMap(point=>{
      const value=point[metric];
      return isMetric(value) ? [{timestamp:point.collectedAt,value}] : [];
    });
  }
  function historyMetricDomain(metric:TelemetryMetric) {
    const values=historyMetricPoints(metric).map(point=>point.value);
    if(!values.length) return undefined;
    const min=Math.min(...values), max=Math.max(...values);
    const padding=Math.max((max-min)*.12, metric==='powerWatts'?10:.5);
    return {min:min-padding,max:max+padding};
  }
  function historyMetricPath(metric:TelemetryMetric) {
    const points=historyMetricPoints(metric), domain=historyMetricDomain(metric), history=telemetryHistory;
    if(!points.length||!domain||!history) return '';
    const span=Math.max(history.endAt-history.startAt,1), valueSpan=Math.max(domain.max-domain.min,1);
    return points.map(point=>`${((point.timestamp-history.startAt)/span*1000).toFixed(1)},${(220-(point.value-domain.min)/valueSpan*184).toFixed(1)}`).join(' ');
  }
  function historyMetricLatest(metric:TelemetryMetric) { return historyMetricPoints(metric).at(-1)?.value; }
  function historyMetricRange(metric:TelemetryMetric) {
    const values=historyMetricPoints(metric).map(point=>point.value);
    if(!values.length) return '暂无数据';
    const format=metric==='powerWatts'?formatWatts:formatTemperature;
    return `${format(Math.min(...values))} – ${format(Math.max(...values))}`;
  }
  function formatHistoryTime(timestamp?:number) {
    return timestamp ? new Date(timestamp*1000).toLocaleString('zh-CN',{month:'numeric',day:'numeric',hour:'2-digit',minute:'2-digit',hour12:false}) : '—';
  }
  function setTarget(identity:string,value:string){targets={...targets,[identity]:value};} function choose(identity:string,value:boolean){picked={...picked,[identity]:value};}
  async function open(ip:string){try{if('__TAURI_INTERNALS__' in window)await openUrl(`https://${ip}`);else window.open(`https://${ip}`,'_blank')}catch{error='无法使用默认浏览器打开 BMC 地址'}}
  const label=(value:string)=>({online:'在线',offline:'离线',reachable:'可用',unreachable:'不可达',success:'成功',failed:'失败',unknown:'未检查',completed:'已完成',adopted_static:'已纳管·静态 IP',pending_reconfiguration:'待重新配置',manual:'手动记录',draft:'待确认',network_changed_unverified:'已变更，待验证'} as Record<string,string>)[value]??value;
</script>

<main>
  <header class="topbar"><div class="brand"><svg class="brand-mark" viewBox="0 0 42 42" aria-hidden="true"><path d="M8 21 21 8l5 5-8 8 8 8-5 5L8 21Z"/><path d="m21 21 9-9 5 5-4 4 4 4-5 5-9-9Z"/></svg><div><p class="eyebrow">bare metal control plane</p><h1>BMC Fleet <button class="version" onclick={()=>showAbout=true}>v{currentVersion}</button></h1></div></div><span class="local"><i></i>本地控制面已连接</span></header>
  <nav class="app-nav" aria-label="主导航"><button class:active={tab==='overview'} onclick={()=>tab='overview'}><b>总览</b><small>Fleet status</small></button><button class:active={tab==='management'} onclick={()=>{managementClusterFilter='all';tab='management'}}><b>设备清单</b><small>{managed.length} 台已纳管</small></button><button class:active={tab==='clusters'} onclick={()=>tab='clusters'}><b>集群</b><small>{clusters.length} 个编组</small></button><span class="nav-separator" aria-hidden="true">LESSOR 初始化</span><button class:active={tab==='profiles'} onclick={()=>tab='profiles'}><b>初始化凭据</b><small>{profiles.length} 个档案</small></button><button class:active={tab==='inventory'} onclick={openProvisioning}><b>批量初始化</b><small>发现、改密与 IP 配置</small></button><button class:active={tab==='connection'} onclick={()=>tab='connection'}><b>Lessor 设置</b><small>发现源与写入参数</small></button></nav>

  {#if tab==='overview'}
    <section class="fleet-overview"><div class="signal-grid"><article><span>已纳管 BMC</span><strong>{managed.length}</strong><small>跨 {clusters.length} 个集群</small></article><article><span>在线 BMC</span><strong>{totalOnline()}</strong><small>HTTPS 可达并完成最近检查的 BMC 数量</small></article><article class:warning={attentionCount()>0}><span>需要处理</span><strong>{attentionCount()}</strong><small>离线、不可达或认证失败</small></article><article><span>待分组</span><strong>{managed.filter(item=>!item.clusterId).length}</strong><small>请归属到一个集群</small></article></div><div class="overview-section"><div class="section-heading"><div><p class="eyebrow">CLUSTERS</p><h3>集群</h3></div><span>{clusters.length} 个逻辑集群</span></div>{#if clusters.length}<div class="cluster-deck">{#each clusters as cluster}<button class="fleet-cluster {clusterHealth(cluster)}" onclick={()=>openCluster(cluster)}><span class="cluster-index">{String(cluster.id).padStart(2,'0')}</span><span class="cluster-copy"><strong>{cluster.name}</strong><small>{clusterSize(cluster.id)} 台 BMC · {managed.filter(item=>item.clusterId===cluster.id&&item.onlineStatus==='online').length} 台在线</small></span><span class="cluster-state">{clusterHealth(cluster)==='healthy'?'稳定':clusterHealth(cluster)==='attention'?'需处理':clusterHealth(cluster)==='empty'?'空集群':'待检查'}</span><span class="cluster-arrow">↗</span></button>{/each}</div>{:else}<div class="empty-state"><strong>先建立一个集群</strong><p>集群可以代表机房、业务域或计算资源池。创建后即可将 BMC 批量归属并进入操作。</p><button class="secondary" onclick={()=>tab='clusters'}>管理集群</button></div>{/if}</div></section>
  {:else if tab==='inventory'}
    <section class="workspace"><div class="section-title"><div><p class="eyebrow">LESSOR INITIALIZATION</p><h2>批量初始化</h2><p>仅此工作区会向 Lessor 读取候选 BMC，用于批量改密与 IP 配置；不会参与 BMC Fleet 的监控或 Redfish 管理。</p></div><button onclick={refreshProvisioning} disabled={loading||executing}>{loading?(progress||'读取中…'):'从 Lessor 读取候选 BMC'}</button></div>
    {#if rows.length}<div class="bmc-table"><div class="bmc-row table-heading"><span>选择 / BMC</span><span>MAC / 作用域</span><span>凭据档案</span><span>目标静态 IPv4 / 访问</span><span>状态</span></div>{#each rows as row}<div class:frozen={row.frozen} class="bmc-row"><label class="pick"><input type="checkbox" checked={picked[row.identity]} disabled={row.frozen||!row.candidate} onchange={event=>choose(row.identity,event.currentTarget.checked)}/><span><strong>{row.frozen?row.address:row.sourceIp}</strong><small>{row.frozen?`已冻结；来源 ${row.sourceIp}`:row.candidate?candidateLabel(row.candidate):'本地历史记录'}</small></span></label><span><code>{row.mac??'MAC 未返回'}</code><small>{row.scopeName}{row.subnet?` / ${row.subnet}/${row.prefix}`:''}</small></span><select value={profileByRow[row.identity]??''} onchange={event=>selectProfile(row,event.currentTarget.value)}><option value="">选择档案</option>{#each profiles as item}<option value={item.name}>{item.name} · {item.username}</option>{/each}</select><span>{#if row.managed&&editing===row.managed.identity}<input bind:value={editAddress}/><button onclick={()=>saveAddress(row.managed!)}>保存</button>{:else}<input value={targets[row.identity]??''} disabled={row.frozen||!row.candidate} oninput={event=>setTarget(row.identity,event.currentTarget.value)} placeholder="例如 172.16.40.200"/>{#if row.managed}<a href={`https://${row.address}`} onclick={event=>{event.preventDefault();void open(row.address)}}>https://{row.address}</a>{/if}{/if}</span>{#if row.managed}<span><strong>{label(row.managed.configurationStatus)}{row.frozen?' · 已冻结':''}</strong><small>{label(row.managed.onlineStatus)} / {label(row.managed.redfishStatus)} / {label(row.managed.authenticationStatus)}</small><span class="row-actions"><button onclick={()=>{editing=row.managed!.identity;editAddress=row.managed!.currentIp}}>编辑地址</button>{#if row.frozen}<button onclick={()=>reprovision(row.managed!)}>重新配置</button>{/if}<button class="text-danger" onclick={()=>remove(row.managed!)}>删除</button></span></span>{:else}<span><strong>待配置</strong><small>需先核验或执行配置</small></span>{/if}</div>{/each}</div><div class="batch-bar"><span>目标网络：/{targetPrefix}，网关 {targetGateway||'未设置'}</span><button class="secondary" onclick={inspectSelected} disabled={executing||inspecting}>{inspecting?(progress||'核验中…'):'核验并纳管已勾选 BMC'}</button><button class="danger" onclick={execute} disabled={executing||inspecting}>执行已勾选 BMC 的 IP 变更配置</button></div>{:else}<p class="muted">尚未读取到 BMC；请检查 lessor 连接设置。</p>{/if}
    <div class="manual-add"><strong>手动加入清单</strong><input bind:value={manualIp} placeholder="BMC IPv4，例如 172.16.40.200"/><input bind:value={manualMac} placeholder="MAC（可选）"/><select bind:value={manualProfile}><option value="">凭据档案（可选）</option>{#each profiles as item}<option value={item.name}>{item.name}</option>{/each}</select><button class="secondary" onclick={addManual}>加入清单</button></div></section>
  {:else if tab==='management'}
    <section class="workspace fleet-workspace"><div class="section-title"><div><p class="eyebrow">INDEPENDENT REDFISH CONTROL PLANE</p><h2>{managementClusterFilter==='all'?'设备清单':managementClusterFilter==='unassigned'?'未归属设备':clusters.find(cluster=>String(cluster.id)===managementClusterFilter)?.name??'集群设备'}</h2><p>仅使用本地已纳管清单与 Redfish 管理 BMC；选择多台设备即可批量执行电源操作，点击“监控”查看后台自动采集的硬件摘要。</p></div><div class="management-header-actions"><button class="primary" onclick={openManagementAdd}><span aria-hidden="true">＋</span> 新建 BMC</button></div></div><div class="management-filter"><label>集群筛选<select bind:value={managementClusterFilter}><option value="all">全部集群</option><option value="unassigned">未分配集群</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}（{clusterSize(cluster.id)}）</option>{/each}</select></label><label>过滤设备<input bind:value={managementSearch} placeholder="名称、IP、MAC、SN 或机房"/></label><label>自动采集间隔<select value={probeIntervalSecs} onchange={event=>setProbeInterval(Number(event.currentTarget.value))}><option value={15}>15 秒</option><option value={30}>30 秒（默认）</option><option value={60}>60 秒</option><option value={120}>120 秒</option><option value={0}>暂停自动采集</option></select></label><small>自动采集设备状态与硬件监控；此控制台不调用 Lessor，也不会改变 BMC 网络配置。</small></div>
    {#if filteredManaged().length}<div class="bmc-table management-table"><div class="bmc-row table-heading"><label class="pick select-all"><input type="checkbox" checked={allFilteredManagedPicked()} onchange={event=>chooseAllFilteredManaged(event.currentTarget.checked)}/><span>全选当前筛选结果</span></label><span>BMC IP</span><span>BMC MAC</span><span>SN</span><span>登录凭据</span><span>BMC 连接</span><span>服务器电源</span><span>操作</span></div>{#each filteredManaged() as item}<div class="bmc-row"><div class="pick"><input type="checkbox" aria-label={`选择 ${item.displayName||item.currentIp}`} checked={managementPicked[item.identity]} onchange={event=>chooseManaged(item.identity,event.currentTarget.checked)}/><span><button type="button" class="machine-link" onclick={()=>openMachine(item)}>{item.displayName||item.currentIp}</button>
<small>{clusterLabel(item)} · {item.displayName?item.currentIp:'未命名服务器'}{isDraft(item)?'（待确认）':''}</small>
</span></div>
<span><a href={`https://${item.currentIp}`} onclick={event=>{event.preventDefault();void open(item.currentIp)}}>{item.currentIp}</a></span>
<span class="hardware-id" title={item.bmcMac?'管理网口（与 BMC IP 匹配）':item.mac?'来自设备档案，尚未自动确认':'自动采集后显示'}><code>{item.bmcMac??item.mac??'—'}</code></span>
<span class="hardware-id" title={item.serialNumber??'暂未读取到服务器产品序列号'}><code>{item.serialNumber??'—'}</code></span>
<span class="management-credential" title={managedCredentialHint(item)}><strong>{item.credentialUsername||managedCredentialLabel(item)}</strong><small>{item.credentialUsername?'密码已保存':managedCredentialHint(item)}</small></span>
<span class="management-readiness" title={managedReadinessHint(item)}><span class:ready={managedReadiness(item)==='ready'} class:attention={managedReadiness(item)==='attention'} class:pending={managedReadiness(item)==='pending'} class="readiness-dot" aria-hidden="true"></span><strong>{managedReadinessLabel(item)}</strong></span>
<span class="management-power"><span class="power-state-badge {serverPowerView(item).tone}" title={serverPowerView(item).hint}><svg aria-hidden="true" viewBox="0 0 16 16"><path d="M8 1.5v6M4.4 3.6a5.6 5.6 0 1 0 7.2 0"/></svg>{serverPowerView(item).label}</span></span>
<span class="management-operation">{#if managementEditing===item.identity}
<div class="edit-management">
<div class="edit-management-heading"><p class="eyebrow">EDIT BMC</p><strong>{item.displayName||item.currentIp}</strong><small>密码留空时不会修改已保存的设备凭据。</small></div><label>服务器名称<input bind:value={managementEditName} aria-label="服务器名称" placeholder="服务器名称（可选）"/></label><label>BMC IPv4<input bind:value={managementEditIp} aria-label="BMC IPv4" placeholder="BMC IPv4"/></label><label>集群<select bind:value={managementEditCluster} aria-label="集群"><option value="">未分配集群</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}</option>{/each}</select></label><section class="device-credential-edit"><p>设备登录凭据</p><label>用户名<input bind:value={managementEditUsername} aria-label="BMC 用户名" placeholder="例如 admin" autocomplete="username"/></label><label>密码<input bind:value={managementEditPassword} aria-label="BMC 密码" type="password" placeholder={item.credentialUsername?'留空则保持不变':'首次保存时必填'} autocomplete="new-password"/></label><small>密码仅以加密密文写入本地数据库，不会显示或导出。</small></section><span class="edit-management-actions"><button class="secondary compact" onclick={()=>managementEditing=''}>取消</button><button class="primary compact" onclick={()=>saveManagementEdit(item)}>保存更改</button></span></div>
{:else}<PowerControls enabled={action=>!managementBusy&&supportsPower(item,action)} hint={action=>powerHint(item,action)} execute={action=>{void powerOne(item,action)}}/><span class="row-actions">
<button class="compact" onclick={()=>beginManagementEdit(item)}>编辑</button><button class="compact" onclick={()=>duplicateManagementBmc(item)}>复制新建</button>
<button class="text-danger compact" onclick={()=>remove(item)}>删除</button></span>{/if}</span></div>{/each}</div><div class="batch-bar management-actions"><span>已选择 {pickedManaged().length} 台 BMC</span><PowerControls batch enabled={action=>!managementBusy&&pickedManaged().some(item=>supportsPower(item,action))} hint={action=>powerDescriptions[action]} execute={action=>{void executeManagementPower(action)}}/></div>{:else}<p class="muted">当前筛选没有 BMC。可切换集群筛选，或点击右上角“新建 BMC”。</p>{/if}
    </section>
  {:else if tab==='clusters'}
    <section class="workspace cluster-workspace"><div class="section-title"><div><p class="eyebrow">FLEET ORGANIZATION</p><h2>集群</h2><p>集群与成员归属仅保存在本地 BMC Fleet 中，用于组织 Redfish 管理范围；点击卡片即可进入该集群的 BMC 清单。</p></div><span class="cluster-total">{clusters.length} 个集群</span></div><div class="cluster-create"><label>集群名称<input bind:value={clusterName} placeholder="例如 B300-训练集群-A" disabled={clusterCreating}/></label><button class="primary" onclick={createCluster} disabled={clusterCreating}>{clusterCreating?'创建中…':'新建集群'}</button></div>{#if error}<p class="form-error" role="alert">{error}</p>{/if}{#if clusters.length}<div class="cluster-card-grid">{#each clusters as cluster}<article class:editing={editingCluster===cluster.id} class:healthy={clusterHealth(cluster)==='healthy'} class:attention={clusterHealth(cluster)==='attention'} class:empty={clusterHealth(cluster)==='empty'} class="cluster-card">{#if editingCluster===cluster.id}<div class="cluster-edit"><p class="eyebrow">RENAME CLUSTER</p><label><span>集群名称</span><input bind:value={clusterEditName} aria-label="集群名称" onkeydown={event=>{if(event.key==='Enter')void saveCluster(cluster);if(event.key==='Escape')editingCluster=undefined}}/></label><div class="cluster-edit-actions"><button class="secondary" onclick={()=>editingCluster=undefined}>取消</button><button class="primary" onclick={()=>saveCluster(cluster)}>保存更名</button></div></div>{:else}<button type="button" class="cluster-card-main" onclick={()=>openCluster(cluster)}><span class="cluster-card-head"><span class="cluster-card-index">集群 {String(cluster.id).padStart(2,'0')}</span><span class="cluster-card-status">{clusterHealthLabel(cluster)}</span></span><strong>{cluster.name}</strong><span class="cluster-card-metrics"><span><b>{clusterSize(cluster.id)}</b><small>已纳管 BMC</small></span><span><b>{clusterOnlineCount(cluster)}</b><small>在线</small></span><span class:has-attention={clusterAttentionCount(cluster)>0}><b>{clusterAttentionCount(cluster)}</b><small>需处理</small></span></span><span class="cluster-card-foot"><small>{clusterLastChecked(cluster)}</small><span>进入设备清单 <i>→</i></span></span></button><div class="cluster-card-actions"><button class="secondary compact" onclick={()=>openCluster(cluster)}>查看 BMC</button><button class="compact" onclick={()=>beginClusterEdit(cluster)}>编辑</button><button class="text-danger compact" onclick={()=>removeCluster(cluster)}>删除</button></div>{/if}</article>{/each}</div>{:else}<p class="muted">还没有集群。可按业务、机柜或任意名称创建集群。</p>{/if}</section>
  {:else if tab==='connection'}
    <section class="settings-page"><div class="section-title"><div><p class="eyebrow">LESSOR INITIALIZATION ONLY</p><h2>Lessor 设置</h2><p>只供“批量初始化”工作区发现候选 BMC、改密和修改 IP。BMC Fleet 的监控和 Redfish 操作不会读取或调用这些设置。</p></div></div><div class="setting-grid"><label>lessor 地址<input bind:value={lessorUrl} placeholder="http://127.0.0.1:8080"/></label><label>作用域 ID<input bind:value={scopeId} type="number" min="1"/></label></div><div class="setting-grid network"><label>默认 IPv4 前缀<input bind:value={targetPrefix} type="number" min="1" max="32"/></label><label>默认网关<input bind:value={targetGateway} placeholder="172.16.40.254"/></label><label>批量写入并发<select bind:value={batchConcurrency}><option value={1}>1 台（串行）</option><option value={2}>2 台</option><option value={4}>4 台（默认）</option><option value={8}>8 台</option></select></label></div><button class="primary" onclick={saveConnection} disabled={savingConnection}>{savingConnection?'保存中…':'保存 Lessor 设置'}</button></section>
  {:else}
    <section class="settings-page"><div class="section-title"><div><p class="eyebrow">LESSOR INITIALIZATION ONLY</p><h2>初始化凭据</h2><p>只用于尚未纳管 BMC 的 Lessor 批量初始化、首次改密和 IP 配置。纳管后请在“设备清单”逐台维护登录凭据；日常监控和 Redfish 操作不再依赖这里的档案。</p></div></div><div class="profile-form"><label>档案名称<input bind:value={profileName} placeholder="例如 default、rack-a"/></label><label>用户名<input bind:value={profileUsername} placeholder="root"/></label><label>当前密码<input bind:value={profileCurrentPassword} type="password"/></label><label>新密码 <small>首次强制改密时使用</small><input bind:value={profileNewPassword} type="password"/></label><button class="primary" onclick={saveProfile}>保存初始化凭据</button></div><div class="profile-recovery"><span><strong>恢复已有 Windows 初始化凭据</strong><small>升级前的密码仍在凭据管理器时，输入原档案名即可恢复其名称和用户名；不会显示、导出或改写密码。</small></span><input bind:value={restoreProfileName} placeholder="例如 asrr-default" onkeydown={event=>{if(event.key==='Enter')void restoreProfile()}}/><button class="secondary" onclick={restoreProfile}>恢复档案</button></div>{#if profiles.length}<div class="profile-list">{#each profiles as item}<div><span><strong>{item.name}</strong><small>{item.username} · 仅供 Lessor 初始化流程</small></span><button class="text-danger" onclick={()=>removeProfile(item.name)}>删除</button></div>{/each}</div>{:else}<p class="muted">还没有初始化凭据。仅在需要通过 Lessor 批量初始化 BMC 时创建；日常设备管理请直接编辑 BMC 登录凭据。</p>{/if}</section>
  {/if}
  <dialog bind:this={managementAddDialog} class="bmc-create-dialog" aria-labelledby="bmc-create-title" onclose={resetManagementAdd} oncancel={event=>{if(managementAdding)event.preventDefault()}}>
    <form onsubmit={event=>{event.preventDefault();void addManagementBmc()}}>
      <header class="bmc-create-heading"><div><h2 id="bmc-create-title">新建 BMC</h2><p>填写管理地址，将服务器加入设备清单。</p></div><button type="button" class="bmc-create-close" aria-label="关闭新建 BMC" disabled={managementAdding} onclick={()=>managementAddDialog.close()}>×</button></header>
      <fieldset disabled={managementAdding} class="bmc-create-fields">
        <label>BMC IPv4 <span class="required-mark">*</span><input bind:value={managementAddIp} required placeholder="例如 172.16.40.18" autocomplete="off"/></label>
        <label>服务器名称 <span>选填</span><input bind:value={managementAddName} placeholder="例如 b300-14"/></label>
        <label>所属集群<select bind:value={managementAddCluster}><option value="">未分配集群</option>{#each clusters as cluster}<option value={String(cluster.id)}>{cluster.name}</option>{/each}</select></label>
        <label>MAC 地址 <span>选填</span><input bind:value={managementAddMac} placeholder="例如 00:11:22:33:44:55"/></label>
        <div class="bmc-create-credentials"><h3>登录凭据 <span>选填</span></h3><p>填写后自动检查设备并采集监控，也可以稍后在设备编辑中补充。</p></div>
        <label>用户名<input bind:value={managementAddUsername} placeholder="例如 admin" autocomplete="username"/></label>
        <label>密码<input bind:value={managementAddPassword} type="password" placeholder="BMC 登录密码" autocomplete="new-password"/></label>
      </fieldset>
      {#if managementAddError}<p class="bmc-create-error" role="alert">{managementAddError}</p>{/if}
      <footer class="bmc-create-actions"><button type="button" class="secondary" disabled={managementAdding} onclick={()=>managementAddDialog.close()}>取消</button><button type="submit" class="primary" disabled={managementAdding}>{managementAdding?'正在创建…':'创建 BMC'}</button></footer>
    </form>
  </dialog>
  {#if activeMachine}
    <button class="drawer-backdrop" aria-label="关闭监控面板" onclick={()=>activeMachine=undefined}></button>
    <aside class="telemetry-drawer" aria-label="BMC 硬件监控">
      <div class="drawer-heading"><div><p class="eyebrow">BMC TELEMETRY</p><h2>{activeMachine.displayName||activeMachine.currentIp}</h2><p>{activeMachine.currentIp} · {clusterLabel(activeMachine)}</p></div><button class="drawer-close" aria-label="关闭" onclick={()=>activeMachine=undefined}>×</button></div>
      {#if telemetryLoading}
        <div class="telemetry-loading"><span></span>等待后台自动采集 Redfish 资源…</div>
      {:else if telemetry}
        <div class="machine-identity"><span>{telemetry.manufacturer??'Redfish 设备'} · {telemetry.model??'型号未提供'}</span><span>序列号 {telemetry.serialNumber??'未提供'}</span><span>最近自动采集 {telemetryUpdatedAt(activeMachine)}</span></div>
        <div class="metric-board"><article title="来自主机机箱 PowerControl 当前功率；不以 HGX 底板功率代替整机"><span>整机功率</span><strong>{formatWatts(telemetry.powerWatts)}</strong><small>{telemetry.powerWatts==null?'本次未读取到整机功率 · ':''}{telemetry.powerState==='On'?'已开机':telemetry.powerState==='Off'?'已关机':telemetry.powerState??'电源状态未提供'}</small></article><article><span>最高温度</span><strong>{formatTemperature(telemetry.temperatureCelsius)}</strong><small>硬件传感器</small></article><article><span>CPU</span><strong>{telemetry.cpu.cores??'—'} 核</strong><small>{telemetry.cpu.packages||'—'} 路 · {telemetry.cpu.model??'型号未提供'}</small></article><article><span>内存</span><strong>{formatMemory(telemetry.memory.capacityMib)}</strong><small>{telemetry.memory.modules||'—'} 个模块 · {telemetry.memory.health??'状态未提供'}</small></article><article><span>磁盘</span><strong>{formatStorage(telemetry.storage.capacityBytes)}</strong><small>{telemetry.storage.drives||'—'} 块磁盘 · {telemetry.storage.health??'状态未提供'}</small></article><article><span>系统健康</span><strong>{telemetry.health??'未提供'}</strong><small>整体硬件状态</small></article></div>
        <section class="telemetry-trends" aria-label="功率与温度趋势">
          <div class="telemetry-trends-heading"><div><h3>功率与温度趋势</h3><small>原始数据 7 天；聚合趋势最长保留 1 年</small></div><label>时间范围<select value={telemetryRange} onchange={event=>setTelemetryRange(Number(event.currentTarget.value))}><option value={3600}>最近 1 小时</option><option value={21600}>最近 6 小时</option><option value={86400}>最近 24 小时</option><option value={604800}>最近 7 天</option><option value={2592000}>最近 30 天</option><option value={7776000}>最近 90 天</option><option value={31536000}>最近 1 年</option></select></label></div>
          {#if telemetryHistoryLoading}
            <p class="trend-loading">读取本地历史数据…</p>
          {:else if telemetryHistoryError}
            <p class="trend-error">{telemetryHistoryError}</p>
          {:else}
            <div class="trend-chart-grid">
              <article class="trend-chart power"><div class="trend-chart-head"><span>整机功率</span><strong>{formatWatts(historyMetricLatest('powerWatts'))}</strong><small>{historyMetricRange('powerWatts')}</small></div>{#if historyMetricPath('powerWatts')}<svg viewBox="0 0 1000 240" preserveAspectRatio="none" role="img" aria-label="整机功率趋势"><line x1="0" y1="36" x2="1000" y2="36"/><line x1="0" y1="128" x2="1000" y2="128"/><line x1="0" y1="220" x2="1000" y2="220"/><polyline points={historyMetricPath('powerWatts')}/></svg><div class="trend-time-axis"><span>{formatHistoryTime(telemetryHistory?.startAt)}</span><span>{formatHistoryTime(telemetryHistory?.endAt)}</span></div>{:else}<p class="trend-empty">当前时间段尚无功率历史；下一次自动采集后会显示曲线。</p>{/if}</article>
              <article class="trend-chart temperature"><div class="trend-chart-head"><span>最高温度</span><strong>{formatTemperature(historyMetricLatest('temperatureCelsius'))}</strong><small>{historyMetricRange('temperatureCelsius')}</small></div>{#if historyMetricPath('temperatureCelsius')}<svg viewBox="0 0 1000 240" preserveAspectRatio="none" role="img" aria-label="最高温度趋势"><line x1="0" y1="36" x2="1000" y2="36"/><line x1="0" y1="128" x2="1000" y2="128"/><line x1="0" y1="220" x2="1000" y2="220"/><polyline points={historyMetricPath('temperatureCelsius')}/></svg><div class="trend-time-axis"><span>{formatHistoryTime(telemetryHistory?.startAt)}</span><span>{formatHistoryTime(telemetryHistory?.endAt)}</span></div>{:else}<p class="trend-empty">当前时间段尚无温度历史；下一次自动采集后会显示曲线。</p>{/if}</article>
            </div>
            <small class="trend-samples">{telemetryHistory?.points.length??0} 个本地采样点 · 图表会按时间段自动聚合</small>
          {/if}
        </section>
        {#if telemetry.gpu}<GpuPanel data={telemetry.gpu}/>{/if}
        {#if telemetry.hardware}<HardwarePanel data={telemetry.hardware}/>{/if}
      {:else}
        <div class="telemetry-empty"><strong>暂时没有监控数据</strong><p>{telemetryError||'后台尚未完成首次采集。'}</p><small>系统会按设备清单中的自动采集间隔继续重试。</small></div>
      {/if}
    </aside>
  {/if}
  {#if executionLogs.length}<section class="execution-log" aria-live="polite"><div><h2>执行日志</h2><small>{executing ? '任务执行中，日志会持续更新' : '本次任务已结束'}</small></div><ol>{#each executionLogs as item}<li><time>{timestamp(item.timestampMs)}</time><span>{item.message}</span></li>{/each}</ol></section>{/if}
  <footer aria-live="polite">{#if error}<p class="error">{error}</p>{/if}<p>{message}</p></footer>
  {#if showAbout}<UpdateDialog version={currentVersion} onclose={()=>showAbout=false}/>{/if}
</main>
