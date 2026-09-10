<script lang="ts">
  import { checkUpdate, inDesktop, installUpdate } from './desktop';

  let { version, onclose }: { version: string; onclose: () => void } = $props();
  let phase = $state('idle');
  let update = $state<Awaited<ReturnType<typeof checkUpdate>>>(null);
  let progress = $state({ got: 0, total: 0 });
  let error = $state('');

  const desktop = inDesktop();
  const busy = $derived(['checking', 'stopping', 'downloading', 'installing'].includes(phase));
  const percent = $derived(progress.total ? Math.round((progress.got / progress.total) * 100) : 0);
  const mb = (value: number) => `${(value / 1024 / 1024).toFixed(1)} MB`;

  function explain(reason: unknown) {
    const raw = String(reason instanceof Error ? reason.message : reason);
    if (/release JSON|fetch/i.test(raw)) return `无法读取更新信息。请确认可访问 github.com，或稍后重试。(${raw})`;
    if (/signature|verif/i.test(raw)) return `更新包签名验证失败，已拒绝安装。(${raw})`;
    return raw;
  }

  async function check() {
    phase = 'checking'; error = '';
    try {
      update = await checkUpdate();
      phase = update ? 'found' : 'latest';
    } catch (reason) {
      error = explain(reason); phase = 'idle';
    }
  }

  async function install() {
    if (!update) return;
    error = '';
    try {
      await installUpdate(update, (next) => {
        phase = next.stage;
        if (next.stage === 'downloading') progress = { got: next.got ?? 0, total: next.total ?? 0 };
      });
      phase = 'done';
    } catch (reason) {
      error = explain(reason); phase = 'found';
    }
  }
</script>

<div class="scrim" role="button" tabindex="0" aria-label="关闭" onclick={() => !busy && onclose()} onkeydown={(event) => event.key === 'Escape' && !busy && onclose()}></div>
<dialog class="dialog" open aria-label="关于 bmc-provisioner">
  <h2>关于 bmc-provisioner</h2>
  <dl><dt>版本</dt><dd>v{version}</dd><dt>形态</dt><dd>{desktop ? '桌面端' : '浏览器'}</dd></dl>
  <p>通过 lessor 发现 BMC，再以 Redfish 配置凭据和静态 IPv4。</p>
  <p class="links"><a href="https://github.com/weironz/bmc-provisioner" target="_blank" rel="noreferrer">项目主页</a><a href="https://github.com/weironz/bmc-provisioner/releases" target="_blank" rel="noreferrer">发布记录</a></p>

  {#if desktop}
    <div class="update">
      {#if phase === 'idle' || phase === 'latest'}
        <button class="secondary" onclick={check}>检查更新</button>
        {#if phase === 'latest'}<span class="ok">已是最新版本。</span>{/if}
      {:else if phase === 'checking'}<span>正在检查更新…</span>
      {:else if phase === 'found'}
        <strong>有新版本 v{update?.version}</strong>
        {#if update?.body}<pre>{update.body}</pre>{/if}
        <p class="hint">更新会停止本桌面端启动的本地服务，安装完成后自动重启；不会停止独立部署的服务。</p>
        <div class="actions"><button class="primary" onclick={install}>下载并安装</button><button class="secondary" onclick={() => phase = 'idle'}>以后再说</button></div>
      {:else if phase === 'stopping'}<span>正在停止本机服务…</span>
      {:else if phase === 'downloading'}
        <span>正在下载 {progress.total ? `${mb(progress.got)} / ${mb(progress.total)}（${percent}%）` : mb(progress.got)}</span>
        <div class="bar"><i style={`width:${percent}%`}></i></div>
      {:else if phase === 'installing'}<span>正在安装，程序即将重启…</span>
      {:else if phase === 'done'}<span class="ok">安装完成，正在重启。</span>
      {/if}
      {#if error}<p class="error">{error}</p>{/if}
    </div>
  {:else}<p class="hint">自动更新仅在桌面端可用；浏览器部署请按 Docker 或二进制的方式升级。</p>{/if}
  <div class="close"><button class="secondary" onclick={onclose} disabled={busy}>关闭</button></div>
</dialog>

<style>
  .scrim { position:fixed; inset:0; z-index:10; background:rgb(0 0 0 / .35); }
  .dialog { background:#fff; border:1px solid #dce4eb; border-radius:8px; box-shadow:0 16px 45px rgb(0 0 0 / .22); left:50%; max-height:calc(100vh - 32px); overflow:auto; padding:22px; position:fixed; top:50%; transform:translate(-50%,-50%); width:min(460px,calc(100vw - 32px)); z-index:11; }
  h2 { color:#182c3d; font-size:1.1rem; margin:0 0 14px; } dl { display:grid; font-size:.85rem; gap:5px 16px; grid-template-columns:auto 1fr; margin:0 0 14px; } dt { color:#6a7c8d; } dd { margin:0; } p { color:#526c7e; font-size:.84rem; line-height:1.55; } .links { display:flex; gap:14px; margin-top:12px; } a { color:#167c7b; } .update { border-top:1px solid #e6edf2; display:flex; flex-direction:column; gap:10px; margin-top:16px; padding-top:16px; } .primary,.secondary { border-radius:6px; font-weight:700; padding:8px 12px; } .primary { background:#287d7b; border:1px solid #287d7b; color:#fff; } .secondary { background:#fff; border:1px solid #287d7b; color:#176a68; } .actions { display:flex; gap:8px; } pre { background:#f5f7fa; border:1px solid #dce4eb; border-radius:5px; font-size:.75rem; margin:0; max-height:120px; overflow:auto; padding:8px; white-space:pre-wrap; } .hint { color:#86641d; margin:0; } .error { color:#ab3928; font-weight:700; margin:0; } .ok { color:#247348; font-size:.85rem; } .bar { background:#e6edf2; border-radius:4px; height:7px; overflow:hidden; } .bar i { background:#287d7b; display:block; height:100%; transition:width .2s; } .close { display:flex; justify-content:flex-end; margin-top:18px; }
</style>
