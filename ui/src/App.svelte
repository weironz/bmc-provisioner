<script lang="ts">
  import { onDestroy, onMount } from 'svelte';
  import { openUrl } from '@tauri-apps/plugin-opener';

  // Vite and Tauri use a separate UI origin during development / desktop execution. Docker serves
  // this page from bmc-provisionerd itself, so same-origin keeps the browser-side API local.
  const API_BASE = window.location.protocol === 'http:' && window.location.port !== '5173'
    ? window.location.origin
    : 'http://127.0.0.1:6770';

  type Candidate = {
    scopeId: number;
    scopeName: string;
    subnet: string;
    prefix: number;
    ip: string;
    mac?: string;
    firstSeen: number;
    lastSeen: number;
  };

  type Plan = {
    sourceIp: string;
    accountUri: string;
    ethernetInterfaceUri: string;
    currentPasswordChangeRequired: boolean;
    passwordChangeRequested: boolean;
    targetNetwork: { address: string; prefix: number; gateway: string };
  };

  type Job = {
    id: string;
    state: 'queued' | 'running' | 'completed' | 'failed';
    result?: { status: 'completed' | 'network_changed_unverified'; targetIp: string };
    error?: string;
  };

  type StaticDiagnostic = {
    bmcIp: string;
    accountUri: string;
    passwordChangeRequired: boolean;
    ethernetInterfaces: Array<{ uri: string; id: string; name?: string }>;
  };

  type ManagedBmc = {
    identity: string;
    mac?: string;
    scopeId: number;
    scopeName: string;
    sourceIp: string;
    currentIp: string;
    targetNetwork: { address: string; prefix: number; gateway: string };
    configurationStatus: string;
    onlineStatus: string;
    redfishStatus: string;
    authenticationStatus: string;
    lastCheckedAt?: number;
    lastConfiguredAt?: number;
    lastError?: string;
  };

  type EthernetInterface = { uri: string; id: string; name?: string; macAddress?: string; ipv4Addresses: string[]; linkStatus?: string };
  type ApiFailure = { error?: string; details?: { ethernetInterfaces?: EthernetInterface[]; reason?: string } };

  // lessord's HTTP API defaults to 8080. Port 6767 is its DHCP listener,
  // which intentionally does not serve the device-discovery API.
  let lessorUrl = 'http://127.0.0.1:8080';
  let scopeId = 1;
  let candidates: Candidate[] = [];
  let candidateTargets: Record<string, string> = {};
  let managedBmcs: ManagedBmc[] = [];
  let selectedIp = '';
  let knownStaticIp = '';
  let username = 'admin';
  let currentPassword = '';
  let newPassword = '';
  let changePassword = false;
  let targetAddress = '';
  let targetPrefix = 24;
  let targetGateway = '';
  let storeCredentials = false;
  let hasStoredCredentials = false;
  let interfaceUri = '';
  let certificateFingerprint = '';
  let certificateConfirmed = false;
  let knownStaticFingerprint = '';
  let knownStaticFingerprintConfirmed = false;
  let staticDiagnostic: StaticDiagnostic | undefined;
  let interfaceChoices: EthernetInterface[] = [];
  let plan: Plan | undefined;
  let planId = '';
  let job: Job | undefined;
  let message = '先从 lessor 读取已确认的 BMC。';
  let error = '';
  let loadingCandidates = false;
  let planning = false;
  let applying = false;
  let diagnosingStatic = false;
  let loadingManaged = false;
  let checkingManagedIdentity = '';
  let savingDefaults = false;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;

  onDestroy(() => {
    if (pollTimer) clearTimeout(pollTimer);
  });

  onMount(() => { void Promise.all([loadManagedBmcs(), loadDefaults()]); });

  function clearPlan() {
    plan = undefined;
    planId = '';
    job = undefined;
  }

  function choose(candidate: Candidate) {
    selectedIp = candidate.ip;
    certificateFingerprint = '';
    certificateConfirmed = false;
    targetAddress = candidateTargets[candidate.ip] ?? targetAddress;
    clearPlan();
    error = '';
    message = `已选择 ${candidate.ip}${candidate.mac ? `（${candidate.mac}）` : ''}`;
  }

  function setCandidateTarget(candidate: Candidate, target: string) {
    candidateTargets = { ...candidateTargets, [candidate.ip]: target };
    if (selectedIp === candidate.ip) targetAddress = target;
  }

  async function readFailure(response: Response): Promise<ApiFailure> {
    try {
      return (await response.json()) as ApiFailure;
    } catch {
      return {};
    }
  }

  async function loadCandidates() {
    loadingCandidates = true;
    error = '';
    clearPlan();
    try {
      const query = new URLSearchParams({ lessorUrl });
      if (scopeId > 0) query.set('scopeId', String(scopeId));
      const response = await fetch(`${API_BASE}/api/v1/candidates?${query}`);
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? '无法读取 lessor BMC 列表');
      }
      candidates = (await response.json()) as Candidate[];
      candidateTargets = candidates.reduce<Record<string, string>>(
        (targets, candidate) => ({ ...targets, [candidate.ip]: candidateTargets[candidate.ip] ?? '' }),
        {}
      );
      if (candidates.length === 0) {
        message = '当前作用域没有 lessor 已确认的 BMC；请检查 DHCP 租约和 IPMI 识别。';
      } else {
        message = `已读取 ${candidates.length} 台已确认 BMC，请明确选择一台。`;
      }
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '读取 BMC 列表失败';
    } finally {
      loadingCandidates = false;
    }
  }

  async function loadManagedBmcs() {
    loadingManaged = true;
    try {
      const response = await fetch(`${API_BASE}/api/v1/managed-bmcs`);
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? '无法读取本机 BMC 清单');
      }
      managedBmcs = (await response.json()) as ManagedBmc[];
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '读取本机 BMC 清单失败';
    } finally {
      loadingManaged = false;
    }
  }

  /// Open in the operator's normal browser, rather than asking the embedded WebView to create
  /// another window. The browser fallback keeps the Docker/Vite UI useful outside Tauri.
  async function openBmcAddress(address: string) {
    const url = `https://${address}`;
    try {
      if ('__TAURI_INTERNALS__' in window) {
        await openUrl(url);
      } else {
        window.open(url, '_blank', 'noopener,noreferrer');
      }
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '无法使用默认浏览器打开 BMC 地址';
    }
  }

  async function loadDefaults() {
    try {
      const response = await fetch(`${API_BASE}/api/v1/settings/defaults`);
      if (!response.ok) return;
      const result = (await response.json()) as {
        defaults: { lessorUrl: string; scopeId: number; username: string; targetPrefix: number; targetGateway: string };
        hasStoredCredentials: boolean;
      };
      lessorUrl = result.defaults.lessorUrl;
      scopeId = result.defaults.scopeId;
      username = result.defaults.username;
      targetPrefix = result.defaults.targetPrefix;
      targetGateway = result.defaults.targetGateway;
      hasStoredCredentials = result.hasStoredCredentials;
    } catch {
      // The provisioning flow remains usable when defaults cannot be loaded.
    }
  }

  async function saveDefaults() {
    savingDefaults = true;
    error = '';
    try {
      const defaultsResponse = await fetch(`${API_BASE}/api/v1/settings/defaults`, {
        method: 'PUT', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ lessorUrl, scopeId, username, targetPrefix, targetGateway })
      });
      if (!defaultsResponse.ok) throw new Error((await readFailure(defaultsResponse)).error ?? '无法保存默认配置');
      if (storeCredentials) {
        if (!currentPassword || !newPassword) throw new Error('保存凭据前请填写当前密码和新密码。');
        const credentialResponse = await fetch(`${API_BASE}/api/v1/settings/credentials`, {
          method: 'POST', headers: { 'content-type': 'application/json' },
          body: JSON.stringify({ currentPassword, newPassword })
        });
        if (!credentialResponse.ok) throw new Error((await readFailure(credentialResponse)).error ?? '无法保存 Windows 凭据');
        hasStoredCredentials = true;
      }
      message = storeCredentials ? '默认配置已保存；密码已保存至 Windows 凭据管理器。' : '默认配置已保存；密码未保存。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '保存默认配置失败';
    } finally {
      savingDefaults = false;
    }
  }

  async function loadStoredCredentials() {
    error = '';
    try {
      const response = await fetch(`${API_BASE}/api/v1/settings/credentials`);
      if (!response.ok) throw new Error((await readFailure(response)).error ?? '未找到保存的 Windows 凭据');
      const saved = (await response.json()) as { currentPassword: string; newPassword: string };
      currentPassword = saved.currentPassword;
      newPassword = saved.newPassword;
      message = '已从 Windows 凭据管理器加载密码到本次会话。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '加载 Windows 凭据失败';
    }
  }

  async function checkManagedBmc(bmc: ManagedBmc) {
    if (!username || !currentPassword) {
      error = '检查认证状态需要输入当前用户名和密码；凭据不会保存。';
      return;
    }
    checkingManagedIdentity = bmc.identity;
    error = '';
    try {
      const response = await fetch(`${API_BASE}/api/v1/managed-bmcs/${encodeURIComponent(bmc.identity)}/check`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ username, currentPassword })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? 'BMC 状态检查失败');
      }
      const updated = (await response.json()) as ManagedBmc;
      managedBmcs = managedBmcs.map((item) => item.identity === updated.identity ? updated : item);
      message = `${updated.currentIp} 已完成状态检查；密码未保存。`;
    } catch (reason) {
      error = reason instanceof Error ? reason.message : 'BMC 状态检查失败';
    } finally {
      checkingManagedIdentity = '';
    }
  }

  function stateLabel(value: string) {
    return ({ online: '在线', offline: '离线', reachable: '可用', unreachable: '不可达', success: '成功', failed: '失败', unknown: '未检查', completed: '已完成', network_changed_unverified: '待复查' } as Record<string, string>)[value] ?? value;
  }

  function formatTime(seconds?: number) {
    return seconds ? new Date(seconds * 1000).toLocaleString() : '未检查';
  }

  function interfaceLabel(item: EthernetInterface) {
    const addresses = item.ipv4Addresses.length ? item.ipv4Addresses.join(', ') : '无 IPv4 地址';
    return `${item.name ?? item.id} · ${addresses}${item.macAddress ? ` · ${item.macAddress}` : ''}${item.linkStatus ? ` · ${item.linkStatus}` : ''}`;
  }

  async function createPlan() {
    if (!selectedIp) {
      error = '请先选择 lessor 已确认的 BMC。';
      return;
    }
    planning = true;
    error = '';
    clearPlan();
    try {
      const response = await fetch(`${API_BASE}/api/v1/provision/plan`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          lessorUrl,
          scopeId,
          candidateIp: selectedIp,
          credentials: { username, currentPassword, newPassword },
          targetNetwork: { address: targetAddress, prefix: targetPrefix, gateway: targetGateway },
          ethernetInterfaceUri: interfaceUri || undefined,
          certificateFingerprint: certificateConfirmed ? certificateFingerprint : undefined,
          passwordChange: changePassword
        })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        interfaceChoices = failure.details?.ethernetInterfaces ?? [];
        throw new Error(failure.details?.reason ?? failure.error ?? 'BMC 无法生成配置计划');
      }
      const result = (await response.json()) as { planId: string; plan: Plan };
      planId = result.planId;
      plan = result.plan;
      changePassword = result.plan.passwordChangeRequested;
      interfaceChoices = [];
      message = '计划已生成。请核对账户、管理网卡和目标地址，然后执行。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '创建计划失败';
    } finally {
      planning = false;
    }
  }

  async function probeCertificate() {
    if (!selectedIp) {
      error = '请先选择 lessor 已确认的 BMC。';
      return;
    }
    error = '';
    certificateConfirmed = false;
    try {
      const response = await fetch(`${API_BASE}/api/v1/certificates/probe`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ lessorUrl, scopeId, candidateIp: selectedIp })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? '无法读取 BMC HTTPS 证书');
      }
      const result = (await response.json()) as { fingerprint: { sha256: string } };
      certificateFingerprint = result.fingerprint.sha256;
      message = '已读取 BMC 证书指纹。确认后，Redfish 仅信任此证书。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '读取证书失败';
    }
  }

  async function probeKnownStaticCertificate() {
    if (!knownStaticIp) {
      error = '请填写已知静态 BMC IP。';
      return;
    }
    error = '';
    knownStaticFingerprintConfirmed = false;
    try {
      const response = await fetch(`${API_BASE}/api/v1/diagnostics/redfish/certificate`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ bmcIp: knownStaticIp })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? '无法读取静态 BMC HTTPS 证书');
      }
      const result = (await response.json()) as { sha256: string };
      knownStaticFingerprint = result.sha256;
      message = '已读取静态 BMC 证书指纹。确认后可进行只读 Redfish 诊断。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '读取静态 BMC 证书失败';
    }
  }

  async function diagnoseKnownStaticBmc() {
    if (!knownStaticIp || !username || !currentPassword) {
      error = '只读诊断需要静态 BMC IP、用户名和当前密码。';
      return;
    }
    diagnosingStatic = true;
    error = '';
    staticDiagnostic = undefined;
    try {
      const response = await fetch(`${API_BASE}/api/v1/diagnostics/redfish`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          bmcIp: knownStaticIp,
          credentials: { username, currentPassword },
          certificateFingerprint: knownStaticFingerprintConfirmed ? knownStaticFingerprint : undefined
        })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? '静态 BMC Redfish 诊断失败');
      }
      staticDiagnostic = (await response.json()) as StaticDiagnostic;
      message = '只读 Redfish 诊断完成；未创建配置计划，也未对 BMC 发出修改请求。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '静态 BMC 诊断失败';
    } finally {
      diagnosingStatic = false;
    }
  }

  async function applyPlan() {
    if (!planId) return;
    applying = true;
    error = '';
    try {
      const response = await fetch(`${API_BASE}/api/v1/provision/plans/${planId}/apply`, {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ credentials: { username, currentPassword, newPassword } })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        throw new Error(failure.error ?? '无法执行配置计划');
      }
      job = (await response.json()) as Job;
      message = plan?.passwordChangeRequested
        ? '已提交配置任务：正在改密、写入静态网络并验证新地址。'
        : '已提交配置任务：正在写入静态网络并验证新地址。';
      await pollJob();
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '提交任务失败';
    } finally {
      applying = false;
    }
  }

  async function pollJob() {
    if (!job) return;
    const response = await fetch(`${API_BASE}/api/v1/jobs/${job.id}`);
    if (!response.ok) {
      const failure = await readFailure(response);
      error = failure.error ?? '无法读取任务状态';
      return;
    }
    job = (await response.json()) as Job;
    if (job.state === 'queued' || job.state === 'running') {
      pollTimer = setTimeout(pollJob, 1500);
      return;
    }
    if (job.state === 'completed') {
      // ProvisionWorkflow has already authenticated through the new address. Reload the
      // durable record immediately so this run's online/Redfish/authentication state appears
      // without requiring the operator to click the later health-check button.
      await loadManagedBmcs();
      message = job.result?.status === 'completed'
        ? `配置完成，已在 ${job.result.targetIp} 验证 Redfish 登录；清单与访问状态已自动刷新。`
        : '网络已写入，但暂未能通过新地址验证；请检查链路与目标网络。';
    } else {
      error = job.error ?? 'BMC 配置失败';
    }
  }
</script>

<svelte:head>
  <meta name="description" content="为 lessor 已确认的单台 BMC 配置 Redfish 密码和静态 IPv4" />
</svelte:head>

<main>
  <header>
    <div>
      <p class="eyebrow">single BMC provisioning</p>
      <h1>bmc-provisioner</h1>
    </div>
    <span class="local">仅本机 localhost</span>
  </header>

  <p class="notice">密码只在本次浏览器请求中使用，不会显示在计划或任务结果中。BMC 使用自签名 HTTPS 证书时，必须先读取并确认指纹。</p>

  <section aria-labelledby="lessor-heading">
    <div class="section-title">
      <div>
        <p class="step">01</p>
        <h2 id="lessor-heading">从 lessor 选择 BMC</h2>
      </div>
      <button onclick={loadCandidates} disabled={loadingCandidates}>
        {loadingCandidates ? '正在读取…' : '读取已确认 BMC'}
      </button>
    </div>
    <div class="fields compact">
      <label>lessor 地址 <input bind:value={lessorUrl} inputmode="url" /></label>
      <label>作用域 ID <input bind:value={scopeId} type="number" min="1" /></label>
    </div>
    {#if candidates.length > 0}
      <div class="candidate-list" aria-label="已确认 BMC">
        <div class="candidate header-row"><span>作用域 / 当前地址</span><span>MAC</span><span>目标静态 IP（草稿）</span><span></span></div>
        {#each candidates as candidate}
          <div class:selected={selectedIp === candidate.ip} class="candidate">
            <span><strong>{candidate.ip}</strong><small>{candidate.scopeName} / {candidate.subnet}/{candidate.prefix}</small></span>
            <code>{candidate.mac ?? 'MAC 未返回'}</code>
            <input value={candidateTargets[candidate.ip] ?? ''} oninput={(event) => setCandidateTarget(candidate, event.currentTarget.value)} inputmode="decimal" placeholder="例如 10.10.20.101" />
            <button onclick={() => choose(candidate)}>{selectedIp === candidate.ip ? '已选择' : '配置此台'}</button>
          </div>
        {/each}
      </div>
    {/if}
    <div class="static-diagnostic">
      <div>
        <p class="step">可选，只读</p>
        <h3>已知静态 BMC 诊断</h3>
        <p>用于已配置静态地址、尚未被 lessor 发现的 BMC。此通道只允许 TLS/Redfish GET，不会产生计划或执行按钮。</p>
      </div>
      <div class="static-controls">
        <label>静态 BMC IP <input bind:value={knownStaticIp} inputmode="decimal" placeholder="172.16.40.35" /></label>
        <button onclick={probeKnownStaticCertificate} disabled={!knownStaticIp}>读取证书指纹</button>
      </div>
      {#if knownStaticFingerprint}
        <label class="fingerprint-confirmation">
          <input bind:checked={knownStaticFingerprintConfirmed} type="checkbox" />
          <span>我确认静态 BMC 的 SHA-256 证书指纹：<code>{knownStaticFingerprint}</code></span>
        </label>
      {/if}
      <button class="read-only" onclick={diagnoseKnownStaticBmc} disabled={diagnosingStatic || !knownStaticIp}>
        {diagnosingStatic ? '正在读取 Redfish…' : '只读检查 Redfish 资源'}
      </button>
      {#if staticDiagnostic}
        <dl class="plan diagnostic-result">
          <div><dt>BMC IP</dt><dd>{staticDiagnostic.bmcIp}</dd></div>
          <div><dt>账户资源</dt><dd>{staticDiagnostic.accountUri}</dd></div>
          <div><dt>强制改密</dt><dd>{staticDiagnostic.passwordChangeRequired ? '是' : '否'}</dd></div>
          <div><dt>管理网卡</dt><dd>{staticDiagnostic.ethernetInterfaces.map((item) => item.name ?? item.id).join('，')}</dd></div>
        </dl>
      {/if}
    </div>
  </section>

  <section aria-labelledby="network-heading">
    <div class="section-title">
      <div>
        <p class="step">02</p>
        <h2 id="network-heading">填写新凭据与网络</h2>
      </div>
    </div>
    <div class="fields">
      <label>用户名 <input bind:value={username} autocomplete="username" /></label>
      <label>当前密码 <input bind:value={currentPassword} type="password" autocomplete="current-password" /></label>
      <label>新密码 <input bind:value={newPassword} type="password" autocomplete="new-password" /></label>
      <label class="password-change-toggle"><input bind:checked={changePassword} type="checkbox" />此次配置同时修改 BMC 密码</label>
      <label>目标 IPv4 <input bind:value={targetAddress} inputmode="decimal" placeholder="192.168.10.20" /></label>
      <label>前缀 <input bind:value={targetPrefix} type="number" min="1" max="32" /></label>
      <label>网关 <input bind:value={targetGateway} inputmode="decimal" placeholder="192.168.10.1" /></label>
    </div>
    <div class="defaults-panel">
      <div>
        <strong>默认配置</strong>
        <p>用户名、lessor 地址、作用域、前缀和网关保存到本机 SQLite。每次只需填写本台 BMC 的目标 IPv4。</p>
      </div>
      <label class="save-credentials">
        <input bind:checked={storeCredentials} type="checkbox" />
        <span>同时将当前密码和新密码安全保存到 Windows 凭据管理器</span>
      </label>
      <div class="defaults-actions">
        <button onclick={saveDefaults} disabled={savingDefaults}>{savingDefaults ? '正在保存…' : '保存默认配置'}</button>
        {#if hasStoredCredentials}<button class="secondary" onclick={loadStoredCredentials}>加载保存的密码</button>{/if}
      </div>
    </div>
    <div class="certificate">
      <div>
        <strong>自签名 HTTPS 证书</strong>
        <p>标准可信证书可直接生成计划。若 BMC 使用自签名证书，先读取指纹并明确确认；程序不会跳过 TLS 校验。</p>
      </div>
      <button onclick={probeCertificate} disabled={!selectedIp}>读取证书指纹</button>
    </div>
    {#if certificateFingerprint}
      <label class="fingerprint-confirmation">
        <input bind:checked={certificateConfirmed} type="checkbox" />
        <span>我确认此 BMC 的 SHA-256 证书指纹：<code>{certificateFingerprint}</code></span>
      </label>
    {/if}
    {#if interfaceChoices.length > 0}
      <label class="interface-choice">未能从当前 DHCP 地址或 MAC 唯一识别管理网卡，请选择
        <select bind:value={interfaceUri}>
          <option value="">请选择 Redfish EthernetInterface</option>
          {#each interfaceChoices as item}<option value={item.uri}>{interfaceLabel(item)}</option>{/each}
        </select>
      </label>
    {/if}
    <button class="primary" onclick={createPlan} disabled={planning || !selectedIp}>
      {planning ? '正在读取 Redfish…' : '生成配置计划'}
    </button>
  </section>

  <section aria-labelledby="execute-heading">
    <div class="section-title">
      <div>
        <p class="step">03</p>
        <h2 id="execute-heading">确认并执行</h2>
      </div>
    </div>
    {#if plan}
      <dl class="plan">
        <div><dt>当前 BMC IP</dt><dd>{plan.sourceIp}</dd></div>
        <div><dt>账户资源</dt><dd>{plan.accountUri}</dd></div>
        <div><dt>管理网卡</dt><dd>{plan.ethernetInterfaceUri}</dd></div>
        <div><dt>首次强制改密</dt><dd>{plan.currentPasswordChangeRequired ? '是' : '否'}</dd></div>
        <div><dt>本次改密</dt><dd>{plan.passwordChangeRequested ? '是' : '否，仅配置网络'}</dd></div>
        <div><dt>新网络</dt><dd>{plan.targetNetwork.address}/{plan.targetNetwork.prefix}，网关 {plan.targetNetwork.gateway}</dd></div>
      </dl>
      <button class="danger" onclick={applyPlan} disabled={applying}>
        {applying ? '正在提交…' : plan.passwordChangeRequested ? '确认：修改密码并切换到静态 IP' : '确认：切换到静态 IP'}
      </button>
    {:else}
      <p class="muted">生成计划后才会显示即将修改的 Redfish 资源。</p>
    {/if}
  </section>

  <section aria-labelledby="managed-heading">
    <div class="section-title">
      <div>
        <p class="step">04</p>
        <h2 id="managed-heading">BMC 清单与访问状态</h2>
      </div>
      <button onclick={loadManagedBmcs} disabled={loadingManaged}>{loadingManaged ? '正在刷新…' : '刷新清单'}</button>
    </div>
    <p class="muted inventory-note">清单保存在本机 SQLite，只记录 MAC、地址、配置结果和状态，不保存密码。认证检查使用上方当前凭据。</p>
    {#if managedBmcs.length > 0}
      <div class="inventory-table" aria-label="已配置 BMC 清单">
        <div class="inventory-row table-heading"><span>BMC / MAC</span><span>访问地址</span><span>配置</span><span>在线 / Redfish / 认证</span><span>最后检查</span><span></span></div>
        {#each managedBmcs as bmc}
          <div class="inventory-row">
            <span><strong>{bmc.currentIp}</strong><small>{bmc.mac ?? bmc.identity} · {bmc.scopeName}</small></span>
            <a href={`https://${bmc.currentIp}`} onclick={(event) => { event.preventDefault(); void openBmcAddress(bmc.currentIp); }}>https://{bmc.currentIp}</a>
            <span class:warning={bmc.configurationStatus !== 'completed'}>{stateLabel(bmc.configurationStatus)}</span>
            <span><i class:online={bmc.onlineStatus === 'online'}>{stateLabel(bmc.onlineStatus)}</i> / {stateLabel(bmc.redfishStatus)} / {stateLabel(bmc.authenticationStatus)}</span>
            <span>{formatTime(bmc.lastCheckedAt)}</span>
            <button onclick={() => checkManagedBmc(bmc)} disabled={checkingManagedIdentity === bmc.identity}>{checkingManagedIdentity === bmc.identity ? '检查中…' : '检查'}</button>
          </div>
        {/each}
      </div>
    {:else}
      <p class="muted">配置过的 BMC 会自动进入这里；也会保留“网络已变更、待复查”与失败记录，方便后续单独检查。</p>
    {/if}
  </section>

  <footer aria-live="polite">
    {#if error}<p class="error">{error}</p>{/if}
    <p>{message}</p>
    {#if job}<p class="job">任务 {job.id}：{job.state}</p>{/if}
  </footer>
</main>
