<script lang="ts">
  import { reading, present, healthLabel, type HardwareTelemetry } from './telemetry';
  let { data }: { data: HardwareTelemetry } = $props();
</script>

{#if data.fans.length || data.powerSupplies.length || data.drives.length || data.networkPorts.length}
  <section class="hardware-panel" aria-label="硬件明细">
    <h3>硬件明细</h3>
    <div class="groups">
      {#if data.fans.length}<details><summary>风扇 <span>{data.fans.length} 个</span></summary><ul>{#each data.fans as fan}<li><strong>{fan.name || '风扇'}</strong><span>{reading(fan.reading, fan.units || '')}</span><small>{healthLabel(fan.health)} · {healthLabel(fan.state)}</small></li>{/each}</ul></details>{/if}
      {#if data.powerSupplies.length}<details><summary>电源模块 <span>{data.powerSupplies.length} 个</span></summary><ul>{#each data.powerSupplies as psu}<li><strong>{psu.name || psu.model || '电源模块'}</strong><span>{healthLabel(psu.health)} · {healthLabel(psu.state)}</span><small>输入 {reading(psu.inputWatts,'W')} · 输出 {reading(psu.outputWatts,'W')} · 额定 {reading(psu.capacityWatts,'W')}</small></li>{/each}</ul></details>{/if}
      {#if data.drives.length}<details><summary>磁盘 <span>{data.drives.length} 块</span></summary><ul>{#each data.drives as drive}<li><strong>{drive.name || drive.model || '磁盘'}</strong><span>{healthLabel(drive.health)} · {present(drive.capacityBytes) ? reading(drive.capacityBytes / 1024**3,'GiB') : '容量未提供'}</span><small>剩余寿命 {reading(drive.lifeLeftPercent,'%')} · {drive.failurePredicted === true ? '预测故障' : drive.failurePredicted === false ? '未预测到故障' : '故障预测未提供'}</small></li>{/each}</ul></details>{/if}
      {#if data.networkPorts.length}<details><summary>主机网口 <span>{data.networkPorts.length} 个</span></summary><ul>{#each data.networkPorts as port}<li><strong>{port.name || '网口'}</strong><span>{healthLabel(port.linkStatus)} · {reading(port.speedMbps,'Mbps')}</span><small>{port.mac || 'MAC 未提供'} · {healthLabel(port.health)}</small></li>{/each}</ul></details>{/if}
    </div>
    <p class="note">仅展示 BMC 返回的硬件资源；未返回的类别不代表设备不存在。</p>
  </section>
{/if}

<style>
  .hardware-panel { margin:20px 0; border:0; background:transparent; } h3 { margin:0 0 10px; font-size:1rem; }
  .groups { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr)); gap:8px; align-items:start; }
  details { border:1px solid #dce3d8; background:#fff; min-width:0; } details[open] { grid-column:1/-1; } summary { padding:11px 12px; min-height:40px; cursor:pointer; font-weight:600; font-size:.8rem; } summary span { float:right; color:#718165; font-size:.75rem; font-variant-numeric:tabular-nums; } summary:focus-visible { outline:2px solid #8cc63f; outline-offset:2px; }
  ul { display:grid; grid-template-columns:repeat(2,minmax(0,1fr)); gap:0 20px; margin:0; padding:0 12px; list-style:none; } li { display:grid; grid-template-columns:minmax(0,1fr) auto; gap:4px 12px; border-top:1px solid #e4eadf; padding:8px 0; overflow-wrap:anywhere; } li strong { font-size:.78rem; } li span { font-size:.75rem; font-variant-numeric:tabular-nums; } li small { grid-column:1/-1; } li small,.note { color:#718174; font-size:.7rem; line-height:1.5; } .note { margin-top:8px; }
  @media(max-width:900px) { .groups { grid-template-columns:repeat(2,minmax(0,1fr)); } ul { grid-template-columns:1fr; } }
  ul { max-height:320px; overflow-y:auto; }
</style>
