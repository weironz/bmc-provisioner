export type PowerAction = 'on' | 'shutdown' | 'restart' | 'force_off' | 'force_restart' | 'power_cycle';
export const primaryPowerActions: PowerAction[] = ['on', 'shutdown', 'restart'];
export const advancedPowerActions: PowerAction[] = ['force_off', 'force_restart', 'power_cycle'];
export const powerActionNames: Record<PowerAction, string> = {
  on: '开机', shutdown: '正常关机', restart: '正常重启',
  force_off: '强制关机', force_restart: '强制重启', power_cycle: '断电重启',
};
export const powerDescriptions: Record<PowerAction, string> = {
  on: '启动服务器电源。',
  shutdown: '请求操作系统正常退出后关机，需要系统响应。',
  restart: '请求操作系统正常退出后重启，需要系统响应。',
  force_off: '立即关闭服务器电源，不等待系统退出；未保存的数据可能丢失。',
  force_restart: '立即强制复位并重启，不等待系统退出；未保存的数据可能丢失。',
  power_cycle: '先关闭服务器电源再重新上电；不等待系统退出，未保存的数据可能丢失。',
};
export function isForcedPowerAction(action: PowerAction) { return advancedPowerActions.includes(action); }
export function isPowerOffAction(action: PowerAction) { return action === 'shutdown' || action === 'force_off'; }
