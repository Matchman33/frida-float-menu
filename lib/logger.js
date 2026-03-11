export function log(message) {
    console.log(message);
}
export class Logger {
    on(arg0, arg1) {
        throw new Error("Method not implemented.");
    }
    static get instance() {
        if (!Logger._instance)
            Logger._instance = new Logger("info");
        return Logger._instance;
    }
    constructor(level = "info", options) {
        this.levelPriority = {
            debug: 0,
            info: 1,
            warn: 2,
            error: 3,
            none: 4,
        };
        this.head = 0;
        this.size = 0;
        this.pending = [];
        this.flushTimer = null;
        this.listeners = [];
        this.currentLevel = level;
        this.maxBuffer = Math.max(50, options?.maxBuffer ?? 300);
        this.flushIntervalMs = Math.max(8, options?.flushIntervalMs ?? 16);
        this.buffer = new Array(this.maxBuffer);
    }
    setLevel(level) {
        this.currentLevel = level;
    }
    setMaxBuffer(max) {
        const newMax = Math.max(50, max | 0);
        if (newMax === this.maxBuffer)
            return;
        const items = this.getRecent(newMax);
        this.maxBuffer = newMax;
        this.buffer = new Array(this.maxBuffer);
        this.head = 0;
        this.size = 0;
        for (const it of items)
            this.pushToBuffer(it);
    }
    debug(...args) {
        this._log("debug", ...args);
    }
    info(...args) {
        this._log("info", ...args);
    }
    warn(...args) {
        this._log("warn", ...args);
    }
    error(...args) {
        this._log("error", ...args);
    }
    onLog(listener, replay = true) {
        this.listeners.push(listener);
        if (replay) {
            const recent = this.getRecent(this.maxBuffer);
            if (recent.length)
                listener(recent);
        }
        return () => {
            const idx = this.listeners.indexOf(listener);
            if (idx >= 0)
                this.listeners.splice(idx, 1);
        };
    }
    getRecent(limit = 200) {
        const n = Math.min(Math.max(1, limit | 0), this.size);
        const out = [];
        if (n <= 0)
            return out;
        const start = (this.head - this.size + this.maxBuffer) % this.maxBuffer;
        const begin = (this.head - n + this.maxBuffer) % this.maxBuffer;
        let i = begin;
        for (let k = 0; k < n; k++) {
            const it = this.buffer[i];
            if (it)
                out.push(it);
            i = (i + 1) % this.maxBuffer;
        }
        return out;
    }
    clear() {
        this.buffer = new Array(this.maxBuffer);
        this.head = 0;
        this.size = 0;
        this.pending.length = 0;
        this.emitBatch([]);
    }
    safeStringify(v) {
        try {
            return JSON.stringify(v);
        }
        catch {
            try {
                return String(v);
            }
            catch {
                return "[Unstringifiable]";
            }
        }
    }
    formatArgs(args) {
        if (!args || args.length === 0)
            return "";
        if (args.length === 1 && typeof args[0] === "string")
            return args[0];
        let out = "";
        for (let i = 0; i < args.length; i++) {
            const a = args[i];
            let s;
            if (typeof a === "string")
                s = a;
            else if (a == null)
                s = String(a);
            else if (typeof a === "number" ||
                typeof a === "boolean" ||
                typeof a === "bigint")
                s = String(a);
            else if (a instanceof Error)
                s = a.stack || a.message || String(a);
            else
                s = this.safeStringify(a);
            if (i === 0)
                out = s;
            else
                out += " " + s;
        }
        return out;
    }
    _log(level, ...args) {
        if (this.levelPriority[level] < this.levelPriority[this.currentLevel])
            return;
        const msg = this.formatArgs(args);
        const item = {
            ts: Date.now(),
            level,
            message: msg,
        };
        switch (level) {
            case "debug":
                console.debug(msg);
                break;
            case "info":
                console.info(msg);
                break;
            case "warn":
                console.warn(msg);
                break;
            case "error":
                console.error(msg);
                break;
        }
        this.pushToBuffer(item);
        this.pending.push(item);
        this.scheduleFlush();
    }
    pushToBuffer(item) {
        this.buffer[this.head] = item;
        this.head = (this.head + 1) % this.maxBuffer;
        if (this.size < this.maxBuffer)
            this.size++;
    }
    scheduleFlush() {
        if (this.flushTimer)
            return;
        this.flushTimer = setTimeout(() => {
            this.flushTimer = null;
            const batch = this.pending;
            this.pending = [];
            this.emitBatch(batch);
        }, this.flushIntervalMs);
    }
    emitBatch(items) {
        if (!this.listeners.length)
            return;
        for (let i = 0; i < this.listeners.length; i++) {
            const fn = this.listeners[i];
            try {
                fn(items);
            }
            catch { }
        }
    }
}
Logger._instance = null;
