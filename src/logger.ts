export function log(message: string): void {
  console.log(message);
}

export type LogLevel = "debug" | "info" | "warn" | "error" | "none";

type LogItem = {
  ts: number;
  level: LogLevel;
  message: string;
};

type LogListener = (items: LogItem[]) => void;

export class Logger {
  on(arg0: string, arg1: (level: LogLevel, message: string) => void) {
    throw new Error("Method not implemented.");
  }
  // ====== 全局单例：外部任何地方都能获取到 ======
  private static _instance: Logger | null = null;
  static get instance(): Logger {
    if (!Logger._instance) Logger._instance = new Logger("info");
    return Logger._instance;
  }

  // ====== 优先级 ======
  private levelPriority: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    none: 4,
  };

  private currentLevel: LogLevel;

  // ====== 环形缓冲（避免内存增长、避免 UI 卡顿） ======
  private maxBuffer: number;
  private buffer: (LogItem | undefined)[];
  private head: number = 0; // 下一次写入位置
  private size: number = 0; // 当前有效长度

  // ====== 批量派发（节流） ======
  private flushIntervalMs: number;
  private pending: LogItem[] = [];
  private flushTimer: any = null;

  // ====== 订阅者（日志窗口/外部） ======
  private listeners: LogListener[] = [];

  constructor(
    level: LogLevel = "info",
    options?: { maxBuffer?: number; flushIntervalMs?: number },
  ) {
    this.currentLevel = level;

    this.maxBuffer = Math.max(50, options?.maxBuffer ?? 300); // 默认保留 300 条
    this.flushIntervalMs = Math.max(8, options?.flushIntervalMs ?? 16); // 默认 ~1 帧批量更新

    this.buffer = new Array(this.maxBuffer);
  }

  // ====== 配置 ======
  setLevel(level: LogLevel): void {
    this.currentLevel = level;
  }

  setMaxBuffer(max: number): void {
    const newMax = Math.max(50, max | 0);
    if (newMax === this.maxBuffer) return;

    // 迁移旧数据到新 buffer（保持时间顺序）
    const items = this.getRecent(newMax);
    this.maxBuffer = newMax;
    this.buffer = new Array(this.maxBuffer);
    this.head = 0;
    this.size = 0;

    for (const it of items) this.pushToBuffer(it);
  }

  // ====== 打日志 ======
  debug(message: string): void {
    this._log("debug", message);
  }
  info(message: string): void {
    this._log("info", message);
  }
  warn(message: string): void {
    this._log("warn", message);
  }
  error(message: string): void {
    this._log("error", message);
  }

  // ====== 给日志窗口订阅（性能版）
  // listener 每次收到的是“批量 items”
  // replay: true -> 立即回放最近 N 条（默认 true）
  onLog(listener: LogListener, replay: boolean = true): () => void {
    this.listeners.push(listener);

    if (replay) {
      const recent = this.getRecent(this.maxBuffer);
      if (recent.length) listener(recent);
    }

    // 返回取消订阅函数
    return () => {
      const idx = this.listeners.indexOf(listener);
      if (idx >= 0) this.listeners.splice(idx, 1);
    };
  }

  // 供 UI 直接拉取（比如抽屉打开时一次性刷新）
  getRecent(limit: number = 200): LogItem[] {
    const n = Math.min(Math.max(1, limit | 0), this.size);
    const out: LogItem[] = [];
    if (n <= 0) return out;

    const start = (this.head - this.size + this.maxBuffer) % this.maxBuffer;
    const begin = (this.head - n + this.maxBuffer) % this.maxBuffer;

    // 从 begin 到 head（按旧->新）
    // 注意：buffer 是环形的，需要分段
    let i = begin;
    for (let k = 0; k < n; k++) {
      const it = this.buffer[i];
      if (it) out.push(it);
      i = (i + 1) % this.maxBuffer;
    }
    return out;
  }

  clear(): void {
    this.buffer = new Array(this.maxBuffer);
    this.head = 0;
    this.size = 0;
    this.pending.length = 0;
    // 也可以通知 UI 清空
    this.emitBatch([]); // 空批次表示“清空”由 UI 自己决定怎么处理
  }

  // ====== 内部实现 ======
  private _log(level: LogLevel, message: string): void {
    console.log(level, message);
    if (this.levelPriority[level] < this.levelPriority[this.currentLevel])
      return;

    const item: LogItem = {
      ts: Date.now(),
      level,
      message,
    };

    // 控制台输出（你也可以按需关掉）
    const formatted = `[${level.toUpperCase()}] ${message}`;
    console.log(formatted);

    // 写入环形缓冲
    this.pushToBuffer(item);

    // 入 pending，走批量派发（避免 UI 每条刷新）
    this.pending.push(item);
    this.scheduleFlush();
  }

  private pushToBuffer(item: LogItem): void {
    this.buffer[this.head] = item;
    this.head = (this.head + 1) % this.maxBuffer;
    if (this.size < this.maxBuffer) this.size++;
  }

  private scheduleFlush(): void {
    if (this.flushTimer) return;

    // 用 setTimeout 节流成批次
    this.flushTimer = setTimeout(() => {
      this.flushTimer = null;

      // 把 pending 一次性取走
      const batch = this.pending;
      this.pending = [];

      // 派发给订阅者
      this.emitBatch(batch);
    }, this.flushIntervalMs);
  }

  private emitBatch(items: LogItem[]): void {
    if (!this.listeners.length) return;

    // 这里不要复制大数组，直接传 items；订阅者不要改它
    for (let i = 0; i < this.listeners.length; i++) {
      const fn = this.listeners[i];
      try {
        fn(items);
      } catch {}
    }
  }
}
