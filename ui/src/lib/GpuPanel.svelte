<script lang="ts">
  import { capacity, reading, present, healthLabel, type GpuTelemetry, type GpuCard } from './telemetry';
  let { data }: { data: GpuTelemetry } = $props();
  const uid = $props.id();
  let expanded = $state<Set<number>>(new Set());
  function toggle(index: number) {
    const next = new Set(expanded);
    if (next.has(index)) next.delete(index); else next.add(index);
    expanded = next;
  }
  function hasEccError(card: GpuCard) { return present(card.uncorrectableEccErrors) && card.uncorrectableEccErrors > 0; }
</script>

{#if data.discovery !== 'absent'}
  <section class="gpu-panel" aria-label="GPU 监控">
    <div class="heading"><h3>GPU 监控</h3>
      {#if data.discovery !== 'unknown'}<div class="summary"><span>已识别 <strong>{data.cards.length}</strong> 张</span><span>可用 <strong>{data.availableCount ?? '—'}</strong> 张</span><span>总显存 <strong>{capacity(data.memoryCapacityMib)}</strong></span></div>{/if}
    </div>
    {#if data.discovery === 'unknown'}
      <p class="notice">暂未确认 GPU 配置，硬件清单读取不完整；下一采集周期会重试。</p>
    {:else}
      {#each data.warnings as warning}<p class="notice">{warning}</p>{/each}
      <div class="table-wrap">
        <table>
          <caption>GPU 当前指标；显存占用率与带宽利用率分开统计</caption>
          <thead><tr><th scope="col">GPU / 型号</th><th scope="col">状态</th><th scope="col">显存容量</th><th scope="col">温度</th><th scope="col">功率</th><th scope="col">GPU 利用率（SM）</th><th scope="col">显存占用率</th><th scope="col"><span class="sr-only">诊断</span></th></tr></thead>
          <tbody>
            {#each data.cards as card, i}
              <tr class="gpu-row" class:expanded={expanded.has(i)}>
                <th scope="row" class="identity"><strong>{card.id}</strong><small title={card.model || '型号未提供'}>{card.model || '型号未提供'}</small></th>
                <td class="state" data-label="状态"><span class="health" class:warning={card.health === 'Warning' || card.health === 'Critical' || hasEccError(card)}>{healthLabel(card.state)} · {hasEccError(card) ? 'ECC 累计异常' : healthLabel(card.health)}</span>{#if card.warnings.length}<small class="partial">部分指标缺失</small>{/if}</td>
                <td class="capacity" data-label="显存容量">{capacity(card.memoryCapacityMib)}</td>
                <td class="temperature" data-label="温度">{reading(card.temperatureCelsius, '°C')}</td>
                <td class="power" data-label="功率">{reading(card.powerWatts, 'W')}</td>
                <td class="utilization" data-label="GPU 利用率（SM）"><span>{reading(card.utilizationPercent, '%')}</span>{#if present(card.utilizationPercent)}<meter min="0" max="100" value={card.utilizationPercent} aria-label={card.id + ' GPU 利用率'}></meter>{/if}</td>
                <td class="memory" data-label="显存占用率"><span>{reading(card.memoryUtilizationPercent, '%')}</span>{#if present(card.memoryUtilizationPercent)}<meter min="0" max="100" value={card.memoryUtilizationPercent} aria-label={card.id + ' 显存占用率'}></meter>{/if}</td>
                <td class="action"><button type="button" aria-label={(expanded.has(i) ? '收起 ' : '展开 ') + card.id + ' 诊断'} aria-expanded={expanded.has(i)} aria-controls={uid + '-diagnostics-' + i} onclick={()=>toggle(i)}>{expanded.has(i) ? '收起' : '详情'}<span aria-hidden="true">{expanded.has(i) ? ' −' : ' +'}</span></button></td>
              </tr>
              <tr class="detail-row" hidden={!expanded.has(i)} id={uid + '-diagnostics-' + i}><td colspan="8">
                <dl class="diagnostics">
                  <div><dt>显存带宽利用率</dt><dd>{reading(card.memoryBandwidthPercent, '%')}</dd></div>
                  <div><dt>功率上限</dt><dd>{reading(card.powerLimitWatts, 'W')}</dd></div>
                  <div><dt>可纠正 ECC（累计）</dt><dd>{reading(card.correctableEccErrors, '', 0)}</dd></div>
                  <div><dt>不可纠正 ECC（累计）</dt><dd class:abnormal={hasEccError(card)}>{reading(card.uncorrectableEccErrors, '', 0)}</dd></div>
                  <div><dt>可纠正行重映射</dt><dd>{reading(card.correctableRowRemaps, '', 0)}</dd></div>
                  <div><dt>不可纠正行重映射</dt><dd>{reading(card.uncorrectableRowRemaps, '', 0)}</dd></div>
                </dl>
                {#each card.warnings as warning}<p class="notice">{warning}</p>{/each}
              </td></tr>
            {/each}
          </tbody>
        </table>
      </div>
      <p class="footnote">自动采集 · 未提供 ≠ 0 · ECC 与带宽指标见每行“详情”</p>
    {/if}
  </section>
{/if}

<style>
  .gpu-panel { margin:20px 0; border:0; background:transparent; }
  .heading { display:flex; align-items:baseline; justify-content:space-between; flex-wrap:wrap; gap:8px 20px; margin-bottom:10px; }
  h3,p { margin:0; } h3 { font-size:1rem; } .summary { display:flex; flex-wrap:wrap; gap:8px 22px; color:#6c7c72; font-size:.78rem; } .summary strong { color:#263a2b; font-variant-numeric:tabular-nums; }
  .table-wrap { border:1px solid #dce3d8; border-top:2px solid #8cc63f; }
  table { width:100%; border-collapse:collapse; table-layout:fixed; text-align:left; background:white; font-size:.8rem; }
  caption,.sr-only { position:absolute; width:1px; height:1px; padding:0; overflow:hidden; clip-path:inset(50%); white-space:nowrap; }
  th,td { padding:9px 10px; vertical-align:middle; text-align:left; border-bottom:1px solid #e6ebe2; font-variant-numeric:tabular-nums; overflow-wrap:anywhere; }
  thead th { background:#f1f5ec; color:#60715f; font-size:.71rem; font-weight:600; padding-block:10px; }
  thead th:first-child { width:19%; } thead th:nth-child(2) { width:16%; } thead th:nth-child(6) { width:13%; } thead th:nth-child(7) { width:12%; } thead th:last-child { width:64px; }
  .identity strong { font-size:.83rem; } small { display:block; font-size:.69rem; line-height:1.5; margin-top:3px; color:#7b887b; font-weight:400; } .identity small { white-space:nowrap; overflow:hidden; text-overflow:ellipsis; }
  .gpu-row:hover,.gpu-row.expanded { background:#f7f9f3; } .health { color:#536e30; font-size:.73rem; } .health.warning,.partial,.abnormal { color:#a26718; }
  meter { display:block; width:100%; max-width:86px; height:4px; margin-top:5px; appearance:none; border:0; background:#edf1e9; } meter::-webkit-meter-bar { border:0; background:#edf1e9; } meter::-webkit-meter-optimum-value { background:#8abc32; }
  .action { padding:4px; } button { border:0; background:transparent; color:#587d22; font-size:.75rem; min-height:40px; min-width:52px; padding:6px; cursor:pointer; } button:hover { background:#eaf0e1; } button:focus-visible { outline:2px solid #8cc63f; outline-offset:1px; }
  .detail-row[hidden] { display:none; } .detail-row>td { background:#f6f8f2; padding:14px 16px; }
  .diagnostics { display:grid; grid-template-columns:repeat(3,minmax(0,1fr)); gap:12px 24px; margin:0; } .diagnostics>div { display:flex; justify-content:space-between; gap:8px; } dt { color:#70816c; font-size:.73rem; } dd { margin:0; font-weight:600; font-size:.8rem; }
  .notice { background:#fff7e9; color:#846023; padding:8px 12px; margin:8px 0; font-size:.76rem; line-height:1.5; }
  .footnote { margin-top:8px; color:#7b887b; font-size:.7rem; }
  @media(max-width:900px) {
    thead { position:absolute; clip-path:inset(50%); width:1px; height:1px; overflow:hidden; }
    .gpu-row { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); grid-template-areas:'identity state capacity action' 'temperature power utilization memory'; border-bottom:1px solid #dce3d8; padding:4px; }
    .gpu-row>th,.gpu-row>td { border:0; padding:6px 8px; }
    .identity { grid-area:identity; } .state { grid-area:state; } .capacity { grid-area:capacity; } .action { grid-area:action; text-align:right; } .temperature { grid-area:temperature; } .power { grid-area:power; } .utilization { grid-area:utilization; } .memory { grid-area:memory; }
    td[data-label]::before { content:attr(data-label); display:block; color:#7b887b; font-size:.67rem; margin-bottom:4px; }
    .detail-row:not([hidden]),.detail-row>td { display:block; } .diagnostics { grid-template-columns:repeat(2,minmax(0,1fr)); }
  }
  @media(max-width:480px) { .diagnostics { grid-template-columns:1fr; } th,td { font-size:.72rem; } .summary { gap:8px 12px; } }
</style>
