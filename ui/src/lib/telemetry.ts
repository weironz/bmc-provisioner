export type GpuCard = {
  id: string; model?: string; state?: string; health?: string;
  memoryCapacityMib?: number; memoryUtilizationPercent?: number; memoryBandwidthPercent?: number;
  utilizationPercent?: number; temperatureCelsius?: number; powerWatts?: number; powerLimitWatts?: number;
  correctableEccErrors?: number; uncorrectableEccErrors?: number;
  correctableRowRemaps?: number; uncorrectableRowRemaps?: number; warnings: string[];
};
export type GpuTelemetry = {
  discovery: 'available'|'absent'|'unknown'|'partial'; availableCount?: number;
  memoryCapacityMib?: number; cards: GpuCard[]; warnings: string[];
};
export type HardwareItem = {
  name?: string; model?: string; state?: string; health?: string;
  reading?: number; units?: string; inputWatts?: number; outputWatts?: number; capacityWatts?: number;
  capacityBytes?: number; lifeLeftPercent?: number; failurePredicted?: boolean;
  linkStatus?: string; speedMbps?: number; mac?: string;
};
export type HardwareTelemetry = { fans: HardwareItem[]; powerSupplies: HardwareItem[]; drives: HardwareItem[]; networkPorts: HardwareItem[] };
export function present(value: unknown): value is number { return typeof value === 'number' && Number.isFinite(value); }
export function reading(value: unknown, unit = '', digits = 1): string {
  return present(value) ? `${value.toLocaleString('zh-CN', { maximumFractionDigits: digits })}${unit ? ` ${unit}` : ''}` : '未提供';
}
export function capacity(mib: unknown): string { return present(mib) ? reading(mib / 1024, 'GiB') : '未提供'; }
export function healthLabel(value?: string): string {
  return ({OK:'正常', Warning:'警告', Critical:'严重', Enabled:'可用', Disabled:'已禁用', Absent:'未安装', UnavailableOffline:'离线', StandbyOffline:'待机', LinkUp:'已连接', LinkDown:'未连接', NoLink:'未连接'} as Record<string,string>)[value ?? ''] ?? value ?? '未知';
}
