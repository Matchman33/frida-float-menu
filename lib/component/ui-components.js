import Java from "frida-java-bridge";
import { EventEmitter } from "../event-emitter.js";
import { applyStyle } from "./style/style.js";
export class UIComponent {
    constructor(id) {
        this.emitter = new EventEmitter();
        this.id = id;
    }
    setMenu(menu) {
        this.menu = menu;
    }
    apply(role, theme) {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => applyStyle(this.view, role, theme));
    }
    getView() {
        return this.view;
    }
    getValue() {
        return this.value;
    }
    getId() {
        return this.id;
    }
    setValue(value) {
        this.value = value;
        this.updateView();
    }
    on(event, listener) {
        this.emitter.on(event, listener);
    }
    off(event, listener) {
        this.emitter.off(event, listener);
    }
    emit(event, ...args) {
        this.emitter.emit(event, ...args);
    }
    init(context) {
        this.createView(context);
    }
    attach() {
    }
    detach() {
    }
}
