/** 桌面壳专属能力；浏览器访问 UI 时不会加载 Tauri IPC 模块。 */
export const inDesktop = () =>
  typeof window !== 'undefined' && '__TAURI_INTERNALS__' in window;

export async function checkUpdate() {
  if (!inDesktop()) return null;
  const { check } = await import('@tauri-apps/plugin-updater');
  return check();
}

export async function installUpdate(
  update: Awaited<ReturnType<typeof checkUpdate>>,
  onStage?: (stage: { stage: string; got?: number; total?: number }) => void,
) {
  if (!update) throw new Error('没有可安装的更新');
  const { invoke } = await import('@tauri-apps/api/core');

  onStage?.({ stage: 'stopping' });
  // 只停桌面壳自己启动的 sidecar，不干预操作者独立运行的服务。
  const stoppedOurs = await invoke<boolean>('stop_local_service');
  let total = 0;
  let got = 0;
  await update.downloadAndInstall((event) => {
    if (event.event === 'Started') {
      total = event.data.contentLength ?? 0;
      onStage?.({ stage: 'downloading', got: 0, total });
    } else if (event.event === 'Progress') {
      got += event.data.chunkLength ?? 0;
      onStage?.({ stage: 'downloading', got, total });
    } else if (event.event === 'Finished') {
      onStage?.({ stage: 'installing' });
    }
  });

  // Windows 安装程序通常会接管并重启；其他平台自行重启。
  try {
    const { relaunch } = await import('@tauri-apps/plugin-process');
    await relaunch();
  } catch {
    // 已被安装程序接管属于正常路径。
  }
  return { stoppedOurs };
}
