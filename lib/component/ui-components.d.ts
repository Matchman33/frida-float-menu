import { EventEmitter } from "../event-emitter.js";
import { FloatMenu } from "../float-menu.js";
export declare abstract class UIComponent {
    protected emitter: EventEmitter;
    protected view: any;
    protected value: any;
    protected id: string;
    protected menu: FloatMenu;
    constructor(id: string);
    setMenu(menu: FloatMenu): void;
    apply(role: any, theme: any): void;
    getView(): any;
    getValue(): any;
    getId(): string;
    setValue(value: any): void;
    on(event: string, listener: (...args: any[]) => void): void;
    off(event: string, listener: (...args: any[]) => void): void;
    protected emit(event: string, ...args: any[]): void;
    protected abstract createView(context: any): void;
    init(context: any): void;
    protected abstract updateView(): void;
    attach(): void;
    detach(): void;
}
