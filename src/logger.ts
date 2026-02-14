export function log(message: string): void {
    console.log(message);
}

export type LogLevel = 'debug' | 'info' | 'warn' | 'error' | 'none';

export class Logger {
    private levelPriority: Record<LogLevel, number> = {
        debug: 0,
        info: 1,
        warn: 2,
        error: 3,
        none: 4
    };
    private currentLevel: LogLevel;
    private emitter: any; // EventEmitter from './event-emitter' but avoid circular dependency

    constructor(level: LogLevel = 'info') {
        this.currentLevel = level;
        // Create a simple emitter to avoid importing EventEmitter
        this.emitter = {
            listeners: new Map(),
            on: function(event: string, listener: Function) {
                if (!this.listeners.has(event)) {
                    this.listeners.set(event, []);
                }
                this.listeners.get(event).push(listener);
            },
            emit: function(event: string, ...args: any[]) {
                const listeners = this.listeners.get(event);
                if (!listeners) return;
                listeners.forEach((listener: Function) => {
                    try {
                        listener(...args);
                    } catch (e) {}
                });
            }
        };
    }

    setLevel(level: LogLevel): void {
        this.currentLevel = level;
    }

    debug(message: string): void {
        this.log('debug', message);
    }

    info(message: string): void {
        this.log('info', message);
    }

    warn(message: string): void {
        this.log('warn', message);
    }

    error(message: string): void {
        this.log('error', message);
    }

    private log(level: LogLevel, message: string): void {
        if (this.levelPriority[level] < this.levelPriority[this.currentLevel]) {
            return;
        }
        const formatted = `[${level.toUpperCase()}] ${message}`;
        console.log(formatted);
        this.emitter.emit('log', level, message);
    }

    on(event: 'log', listener: (level: LogLevel, message: string) => void): void {
        this.emitter.on(event, listener);
    }
}
