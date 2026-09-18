<script lang="ts">
  import { primaryPowerActions, advancedPowerActions, powerActionNames, powerDescriptions, type PowerAction } from './power';
  let { enabled, hint, execute, batch = false }: {
    enabled: (action: PowerAction) => boolean;
    hint: (action: PowerAction) => string;
    execute: (action: PowerAction) => void;
    batch?: boolean;
  } = $props();
  let tooltip = $state<{text:string; x:number; y:number} | null>(null);
  function showTip(event: MouseEvent | FocusEvent, action: PowerAction) {
    const rect = (event.currentTarget as HTMLElement).getBoundingClientRect();
    tooltip = {text: powerDescriptions[action], x: Math.max(8, Math.min(rect.left - 110, window.innerWidth - 272)), y: Math.max(8, rect.top - 88)};
  }
</script>

<div class="power-controls" aria-label={batch ? '批量电源操作' : '电源操作'}>
  {#snippet control(action: PowerAction)}
    <span class="power-choice">
      <button class="power-action" disabled={!enabled(action)} title={hint(action)} onclick={() => execute(action)}>{batch ? '批量' : ''}{powerActionNames[action]}</button>
      {#if action !== 'on'}
        <button class="power-help" type="button" aria-label={`${powerActionNames[action]}：${powerDescriptions[action]}`} onmouseenter={event => showTip(event, action)} onmouseleave={() => tooltip = null} onfocus={event => showTip(event, action)} onblur={() => tooltip = null} onclick={event => showTip(event, action)} onkeydown={event => { if (event.key === 'Escape') tooltip = null; }}>!</button>
      {/if}
    </span>
  {/snippet}
  {#each primaryPowerActions as action}{@render control(action)}{/each}
  <details class="power-more" ontoggle={() => tooltip = null}>
    <summary>更多电源操作</summary>
    <div class="power-advanced">
      {#each advancedPowerActions.filter(action => !batch || action !== 'power_cycle') as action}{@render control(action)}{/each}
    </div>
  </details>
</div>
{#if tooltip}<div class="power-tooltip" role="tooltip" style:left={`${tooltip.x}px`} style:top={`${tooltip.y}px`}>{tooltip.text}</div>{/if}

<style>
  .power-controls { display:flex; align-items:center; flex-wrap:wrap; gap:7px; }
  .power-choice { display:inline-flex; align-items:center; gap:2px; }
  .power-controls .power-action { background:#fff; border:1px solid #aeb9ad; border-radius:3px; color:#435248; font-size:.74rem; padding:6px 8px; margin:0; }
  .power-controls .power-help { display:grid; place-items:center; width:24px; height:28px; padding:0; margin:0; color:#68766b; background:transparent; border:0; font-size:.67rem; font-weight:800; cursor:help; }
  .power-help::before { content:''; position:absolute; width:14px; height:14px; border:1px solid currentColor; border-radius:50%; }
  .power-help:focus-visible, summary:focus-visible { outline:2px solid #83b934; outline-offset:2px; }
  .power-more { flex-basis:100%; }
  summary { cursor:pointer; color:#627168; font-size:.73rem; width:fit-content; padding:5px 0; }
  .power-advanced { display:flex; flex-wrap:wrap; gap:7px; padding:8px; margin-top:3px; background:#fff7f3; border:1px solid #ead9d1; border-radius:3px; }
  .power-advanced .power-action, .power-advanced .power-help { color:#a13e30; }
  .power-tooltip { position:fixed; z-index:10000; width:256px; padding:12px; background:#26312e; color:#fff; border-radius:5px; font-size:.76rem; line-height:1.5; box-shadow:0 4px 16px #0002; pointer-events:none; }
</style>
