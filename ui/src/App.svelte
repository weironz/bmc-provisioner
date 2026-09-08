<script lang="ts">
  import { onDestroy } from 'svelte';

  const API_BASE = 'http://127.0.0.1:6770';

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
    targetNetwork: { address: string; prefix: number; gateway: string };
  };

  type Job = {
    id: string;
    state: 'queued' | 'running' | 'completed' | 'failed';
    result?: { status: 'completed' | 'network_changed_unverified'; targetIp: string };
    error?: string;
  };

  type ApiFailure = { error?: string; details?: { ethernetInterfaceUris?: string[] } };

  let lessorUrl = 'http://127.0.0.1:6767';
  let scopeId = 1;
  let candidates: Candidate[] = [];
  let selectedIp = '';
  let username = 'admin';
  let currentPassword = '';
  let newPassword = '';
  let targetAddress = '';
  let targetPrefix = 24;
  let targetGateway = '';
  let interfaceUri = '';
  let interfaceChoices: string[] = [];
  let plan: Plan | undefined;
  let planId = '';
  let job: Job | undefined;
  let message = '先从 lessor 读取已确认的 BMC。';
  let error = '';
  let loadingCandidates = false;
  let planning = false;
  let applying = false;
  let pollTimer: ReturnType<typeof setTimeout> | undefined;

  onDestroy(() => {
    if (pollTimer) clearTimeout(pollTimer);
  });

  function clearPlan() {
    plan = undefined;
    planId = '';
    job = undefined;
  }

  function choose(candidate: Candidate) {
    selectedIp = candidate.ip;
    clearPlan();
    error = '';
    message = `已选择 ${candidate.ip}${candidate.mac ? `（${candidate.mac}）` : ''}`;
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
          ethernetInterfaceUri: interfaceUri || undefined
        })
      });
      if (!response.ok) {
        const failure = await readFailure(response);
        interfaceChoices = failure.details?.ethernetInterfaceUris ?? [];
        throw new Error(failure.error ?? 'BMC 无法生成配置计划');
      }
      const result = (await response.json()) as { planId: string; plan: Plan };
      planId = result.planId;
      plan = result.plan;
      interfaceChoices = [];
      message = '计划已生成。请核对账户、管理网卡和目标地址，然后执行。';
    } catch (reason) {
      error = reason instanceof Error ? reason.message : '创建计划失败';
    } finally {
      planning = false;
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
      message = '已提交配置任务：正在改密、写入静态网络并验证新地址。';
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
      message = job.result?.status === 'completed'
        ? `配置完成，已在 ${job.result.targetIp} 验证 Redfish 登录。`
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

  <p class="notice">密码只在本次浏览器请求中使用，不会显示在计划或任务结果中。请先确认目标 BMC 的 HTTPS 证书提示。</p>

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
        {#each candidates as candidate}
          <button class:selected={selectedIp === candidate.ip} class="candidate" onclick={() => choose(candidate)}>
            <strong>{candidate.ip}</strong>
            <span>{candidate.mac ?? 'MAC 未返回'} · {candidate.scopeName} / {candidate.subnet}/{candidate.prefix}</span>
          </button>
        {/each}
      </div>
    {/if}
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
      <label>目标 IPv4 <input bind:value={targetAddress} inputmode="decimal" placeholder="192.168.10.20" /></label>
      <label>前缀 <input bind:value={targetPrefix} type="number" min="1" max="32" /></label>
      <label>网关 <input bind:value={targetGateway} inputmode="decimal" placeholder="192.168.10.1" /></label>
    </div>
    {#if interfaceChoices.length > 0}
      <label class="interface-choice">BMC 暴露多块管理网卡，请选择
        <select bind:value={interfaceUri}>
          <option value="">请选择 Redfish EthernetInterface</option>
          {#each interfaceChoices as uri}<option value={uri}>{uri}</option>{/each}
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
        <div><dt>强制改密</dt><dd>{plan.currentPasswordChangeRequired ? '是' : '否（仍将按输入的新密码修改）'}</dd></div>
        <div><dt>新网络</dt><dd>{plan.targetNetwork.address}/{plan.targetNetwork.prefix}，网关 {plan.targetNetwork.gateway}</dd></div>
      </dl>
      <button class="danger" onclick={applyPlan} disabled={applying}>
        {applying ? '正在提交…' : '确认：修改密码并切换到静态 IP'}
      </button>
    {:else}
      <p class="muted">生成计划后才会显示即将修改的 Redfish 资源。</p>
    {/if}
  </section>

  <footer aria-live="polite">
    {#if error}<p class="error">{error}</p>{/if}
    <p>{message}</p>
    {#if job}<p class="job">任务 {job.id}：{job.state}</p>{/if}
  </footer>
</main>
