"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.UIComponent = void 0;
const event_emitter_1 = require("../event-emitter");
const style_1 = require("./style/style");
class UIComponent {
    constructor(id) {
        this.emitter = new event_emitter_1.EventEmitter();
        this.id = id;
    }
    setMenu(menu) {
        this.menu = menu;
    }
    apply(role, theme) {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => (0, style_1.applyStyle)(this.view, role, theme));
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
exports.UIComponent = UIComponent;
