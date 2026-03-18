import { Logger } from "./logger.js";
export class EventEmitter {
    constructor() {
        this.events = new Map();
    }
    on(event, listener) {
        if (!this.events.has(event)) {
            this.events.set(event, []);
        }
        this.events.get(event).push(listener);
    }
    off(event, listener) {
        const listeners = this.events.get(event);
        if (!listeners)
            return;
        const index = listeners.indexOf(listener);
        if (index !== -1) {
            listeners.splice(index, 1);
        }
    }
    emit(event, ...args) {
        const listeners = this.events.get(event);
        if (!listeners)
            return;
        listeners.forEach((listener) => {
            try {
                setImmediate(() => listener(...args));
            }
            catch (error) {
                Logger.instance.error(`Error in event listener for ${event}:`, error);
            }
        });
    }
    once(event, listener) {
        const onceWrapper = (...args) => {
            this.off(event, onceWrapper);
            listener(...args);
        };
        this.on(event, onceWrapper);
    }
    removeAllListeners(event) {
        if (event) {
            this.events.delete(event);
        }
        else {
            this.events.clear();
        }
    }
}
