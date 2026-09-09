<script lang="ts">
  import { onMount } from 'svelte';
  import { openUrl } from '@tauri-apps/plugin-opener';

  const base = window.location.port === '5173' ? 'http://127.0.0.1:6770' : window.location.origin;
  type Candidate = { scopeId:number; scopeName:string; subnet:string; prefix:number; ip:string; mac?:string };
  type Managed = { identity:string; mac?:string; scopeId:number; scopeName:string; sourceIp:string; currentIp:string; configurationStatus:string; onlineStatus:string; redfishStatus:string; authenticationStatus:string; lastCheckedAt?:number };
  type Row = { identity:string; candidate?:Candidate; managed?:Managed; sourceIp:string; address:string; mac?:string; scopeName:string; subnet?:string; prefix?:number; frozen:boolean };

  let lessorUrl = 'http://127.0.0.1:8080';
  let scopeId = 1;
  let username = 'admin';
  let currentPassword = '';
  let newPassword = '';
  let targetPrefix = 24;
  let targetGateway = '';
  let candidates:Candidate[] = [];
  let managed:Managed[] = [];
  let rows:Row[] = [];
  let targets:Record<string,string> = {};
  let picked:Record<string,boolean> = {};
  let manualIp = '';
  let manualMac = '';
  let editing = '';
  let editAddress = '';
  let loading = false;
  let executing = false;
  let message = '正在从 lessor 读取已确认 BMC。';
  let error = '';
  let progress = '';

  onMount(async () => { await defaults(); await Promise.all([load(), inventory()]); });

  async function json(response:Response) { try { return await response.json(); } catch { return {}; } }
  function identityFor(candidate:Candidate) { return (candidate.mac ?? `scope-${candidate.scopeId}-ip-${candidate.ip}`).toLowerCase(); }
  function rebuildRows() {
    const merged = new Map<string, Row>();
    for (const item of managed) {
      merged.set(item.identity.toLowerCase(), {
        identity: item.identity, managed: item, sourceIp: item.sourceIp, address: item.currentIp,
        mac: item.mac, scopeName: item.scopeName, frozen: item.configurationStatus === 'completed',
      });
    }
    for (const candidate of candidates) {
      const identity = identityFor(candidate);
      const current = merged.get(identity);
      merged.set(identity, current ? {
        ...current, candidate: current.frozen ? undefined : candidate, sourceIp: candidate.ip,
        mac: candidate.mac ?? current.mac, scopeName: candidate.scopeName, subnet: candidate.subnet, prefix: candidate.prefix,
      } : {
        identity, candidate, sourceIp: candidate.ip, address: candidate.ip, mac: candidate.mac,
        scopeName: candidate.scopeName, subnet: candidate.subnet, prefix: candidate.prefix, frozen: false,
      });
    }
    rows = [...merged.values()].sort((a, b) => Number(b.frozen) - Number(a.frozen) || a.address.localeCompare(b.address));
    targets = Object.fromEntries(rows.map((row) => [row.identity, targets[row.identity] ?? (row.frozen ? row.address : '')]));
    picked = Object.fromEntries(rows.map((row) => [row.identity, picked[row.identity] ?? false]));
  }
  async function defaults() {
    try {
      const response = await fetch(`${base}/api/v1/settings/defaults`);
      if (!response.ok) return;
      const { defaults: value } = await response.json();
      lessorUrl = value.lessorUrl; scopeId = value.scopeId; username = value.username;
      targetPrefix = value.targetPrefix; targetGateway = value.targetGateway;
    } catch {}
  }
  async function load() {
    try {
      const query = new URLSearchParams({ lessorUrl, scopeId: String(scopeId) });
      const response = await fetch(`${base}/api/v1/candidates?${query}`);
      const value = await json(response);
      if (!response.ok) throw Error(value.error ?? '无法读取 lessor BMC 列表');
      candidates = value; rebuildRows();
    } catch (reason) { error = reason instanceof Error ? reason.message : '读取 lessor 失败'; }
  }
  async function inventory() {
    const response = await fetch(`${base}/api/v1/managed-bmcs`);
    if (!response.ok) throw Error('无法读取本地 BMC 清单');
    managed = await response.json(); rebuildRows();
  }
  async function refresh() {
    loading = true; error = '';
    try {
      await Promise.all([load(), inventory()]);
      if (!managed.length) { message = candidates.length ? `已读取 ${candidates.length} 台待配置 BMC。` : '当前没有可检查的 BMC。'; return; }
      if (!username || !currentPassword) { message = `已刷新清单；填写当前凭据后可检查 ${managed.length} 台 BMC 状态。`; return; }
      const failed:string[] = [];
      for (const [index, item] of managed.entries()) {
        progress = `检查 ${index + 1}/${managed.length}：${item.currentIp}`;
        const response = await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}/check`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ username, currentPassword }),
        });
        if (!response.ok) failed.push(item.currentIp);
      }
      await inventory();
      message = failed.length ? `状态检查完成；${failed.join('、')} 未能完成检查。` : `已更新 ${managed.length} 台 BMC 的在线、Redfish 与认证状态。`;
    } catch (reason) { error = reason instanceof Error ? reason.message : '刷新失败'; }
    finally { loading = false; progress = ''; }
  }
  async function wait(job:any) {
    while (['queued', 'running'].includes(job.state)) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      job = await json(await fetch(`${base}/api/v1/jobs/${job.id}`));
    }
    return job;
  }
  async function execute() {
    const selected = rows.filter((row) => row.candidate && !row.frozen && picked[row.identity]);
    if (!selected.length || !username || !currentPassword || !targetGateway || selected.some((row) => !targets[row.identity])) {
      error = '请勾选待配置 BMC，并填写共用凭据、网关及每台目标 IPv4。'; return;
    }
    await fetch(`${base}/api/v1/settings/defaults`, { method:'PUT', headers:{'content-type':'application/json'}, body:JSON.stringify({ lessorUrl, scopeId, username, targetPrefix, targetGateway }) });
    executing = true; error = '';
    const failed:string[] = [];
    for (const [index, row] of selected.entries()) {
      const candidate = row.candidate!;
      progress = `${index + 1}/${selected.length}：${candidate.ip} → ${targets[row.identity]}`;
      try {
        const certificate = await fetch(`${base}/api/v1/certificates/probe`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ lessorUrl, scopeId, candidateIp:candidate.ip }) });
        const certificateValue:any = await json(certificate);
        if (!certificate.ok) throw Error(certificateValue.error ?? '无法读取 HTTPS 证书');
        const plan = await fetch(`${base}/api/v1/provision/plan`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({ lessorUrl, scopeId, candidateIp:candidate.ip, credentials:{username,currentPassword,newPassword}, targetNetwork:{address:targets[row.identity],prefix:targetPrefix,gateway:targetGateway}, certificateFingerprint:certificateValue.fingerprint.sha256, passwordChange:false }) });
        const planned:any = await json(plan);
        if (!plan.ok) throw Error(planned.details?.reason ?? planned.error ?? '无法生成内部配置');
        const apply = await fetch(`${base}/api/v1/provision/plans/${planned.planId}/apply`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({credentials:{username,currentPassword,newPassword}}) });
        const submitted:any = await json(apply);
        if (!apply.ok) throw Error(submitted.error ?? '无法提交');
        const completed = await wait(submitted);
        if (completed.state !== 'completed') throw Error(completed.error ?? '配置失败');
      } catch (reason) { failed.push(`${candidate.ip}：${reason instanceof Error ? reason.message : '失败'}`); }
    }
    await inventory(); executing = false; progress = '';
    message = `批量任务完成：成功 ${selected.length - failed.length} 台，失败 ${failed.length} 台。成功行已冻结。`;
    if (failed.length) error = failed.join('；');
  }
  async function addManual() {
    if (!manualIp) { error = '请填写要加入清单的 BMC IPv4 地址。'; return; }
    const response = await fetch(`${base}/api/v1/managed-bmcs`, { method:'POST', headers:{'content-type':'application/json'}, body:JSON.stringify({currentIp:manualIp,mac:manualMac || undefined}) });
    const value = await json(response);
    if (!response.ok) { error = value.error ?? '无法添加 BMC'; return; }
    manualIp = ''; manualMac = ''; await inventory(); message = '已添加本地 BMC 清单记录；尚未检查。';
  }
  async function saveAddress(item:Managed) {
    const response = await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`, { method:'PATCH', headers:{'content-type':'application/json'}, body:JSON.stringify({currentIp:editAddress}) });
    const value = await json(response);
    if (!response.ok) { error = value.error ?? '无法更新访问地址'; return; }
    editing = ''; await inventory(); message = '已更新本地清单访问地址；状态待下次检查。';
  }
  async function remove(item:Managed) {
    if (!confirm(`删除本地清单中的 ${item.currentIp}？不会修改 BMC。`)) return;
    const response = await fetch(`${base}/api/v1/managed-bmcs/${encodeURIComponent(item.identity)}`, { method:'DELETE' });
    if (!response.ok) { error = '无法删除本地清单记录'; return; }
    await inventory(); message = '已删除本地清单记录；BMC 未被修改。';
  }
  function setTarget(identity:string, value:string) { targets = { ...targets, [identity]:value }; }
  function choose(identity:string, value:boolean) { picked = { ...picked, [identity]:value }; }
  async function open(ip:string) { try { if ('__TAURI_INTERNALS__' in window) await openUrl(`https://${ip}`); else window.open(`https://${ip}`, '_blank'); } catch { error = '无法使用默认浏览器打开 BMC 地址'; } }
  const label = (value:string) => ({ online:'在线', offline:'离线', reachable:'可用', unreachable:'不可达', success:'成功', failed:'失败', unknown:'未检查', completed:'已完成', manual:'手动记录', network_changed_unverified:'已变更，待验证' } as Record<string,string>)[value] ?? value;
</script>

<main>
  <header><div><p class="eyebrow">BMC provisioning</p><h1>bmc-provisioner</h1></div><span class="local">仅本机 localhost</span></header>
  <p class="notice">lessor 负责动态发现；本地清单负责保存配置结果和历史。刷新会保留历史，并在填写凭据后实际更新在线、Redfish 与认证状态。</p>
  <section>
    <div class="section-title"><div><p class="step">01</p><h2>BMC 配置清单与访问状态</h2></div><button onclick={refresh} disabled={loading || executing}>{loading ? (progress || '刷新中…') : '刷新并检查状态'}</button></div>
    <div class="fields"><label>lessor 地址<input bind:value={lessorUrl} /></label><label>作用域 ID<input bind:value={scopeId} type="number" /></label><label>用户名<input bind:value={username} /></label><label>当前密码<input bind:value={currentPassword} type="password" /></label><label>新密码（首次强制改密时使用）<input bind:value={newPassword} type="password" /></label><label>前缀<input bind:value={targetPrefix} type="number" /></label><label>网关<input bind:value={targetGateway} placeholder="172.16.40.254" /></label></div>
    {#if rows.length}
      <div class="candidate-list merged-list"><div class="candidate header-row merged-row"><span>选择 / BMC</span><span>MAC / 作用域</span><span>目标静态 IPv4 / 访问</span><span>配置与访问状态</span></div>
      {#each rows as row}
        <div class:frozen={row.frozen} class="candidate merged-row">
          <label class="pick"><input type="checkbox" checked={picked[row.identity]} disabled={row.frozen || !row.candidate} onchange={(event) => choose(row.identity, event.currentTarget.checked)} /><span><strong>{row.frozen ? row.address : row.sourceIp}</strong><small>{row.frozen ? `已冻结；来源 ${row.sourceIp}` : row.candidate ? 'lessor 已确认 BMC' : '本地历史记录'}</small></span></label>
          <span><code>{row.mac ?? 'MAC 未返回'}</code><small>{row.scopeName}{row.subnet ? ` / ${row.subnet}/${row.prefix}` : ''}</small></span>
          <span>{#if row.managed && editing === row.managed.identity}<input bind:value={editAddress} /><button onclick={() => saveAddress(row.managed!)}>保存地址</button>{:else}<input value={targets[row.identity] ?? ''} disabled={row.frozen || !row.candidate} oninput={(event) => setTarget(row.identity, event.currentTarget.value)} placeholder="例如 172.16.40.200" />{#if row.managed}<a href={`https://${row.address}`} onclick={(event) => { event.preventDefault(); void open(row.address); }}>https://{row.address}</a>{/if}{/if}</span>
          {#if row.managed}<span><strong>{label(row.managed.configurationStatus)}{row.frozen ? ' · 已冻结' : ''}</strong><small>{label(row.managed.onlineStatus)} / {label(row.managed.redfishStatus)} / {label(row.managed.authenticationStatus)}{row.managed.lastCheckedAt ? ` · ${new Date(row.managed.lastCheckedAt * 1000).toLocaleString()}` : ''}</small><span class="row-actions"><button onclick={() => { editing = row.managed!.identity; editAddress = row.managed!.currentIp; }}>编辑地址</button><button class="text-danger" onclick={() => remove(row.managed!)}>删除</button></span></span>{:else}<span><strong>待配置</strong><small>尚未写入静态 IP</small></span>{/if}
        </div>
      {/each}</div>
      <button class="danger" onclick={execute} disabled={executing}>执行已勾选 BMC 的 IP 变更配置</button>
    {:else}<p class="muted">尚未读取到 BMC；确认 lessor 已发现 BMC 后刷新。</p>{/if}
    <div class="manual-add"><strong>手动加入本地清单</strong><input bind:value={manualIp} placeholder="BMC IPv4，例如 172.16.40.200" /><input bind:value={manualMac} placeholder="MAC（可选）" /><button class="secondary" onclick={addManual}>加入清单</button></div>
  </section>
  <footer aria-live="polite">{#if error}<p class="error">{error}</p>{/if}<p>{message}</p></footer>
</main>
