"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Button = void 0;
const api_1 = require("../api");
const style_1 = require("./style/style");
const ui_components_1 = require("./ui-components");
class Button extends ui_components_1.UIComponent {
    constructor(id, label, kind = "primary", handler) {
        super(id);
        this.kind = "primary";
        this.label = label;
        this.kind = kind;
        this.handler = handler;
        this.value = null;
    }
    createView(context) {
        const Button = api_1.API.Button;
        this.view = Button.$new(context);
        const String = api_1.API.JString;
        this.view.setText(String.$new(this.label));
        (0, style_1.applyStyle)(this.view, this.kind === "danger" ? "dangerButton" : "primaryButton", this.menu.options.theme);
        const OnClickListener = api_1.API.OnClickListener;
        const self = this;
        const clickListener = Java.registerClass({
            name: "com.frida.MyClickListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [OnClickListener],
            methods: {
                onClick: function (v) {
                    self.emit("click");
                    if (self.handler) {
                        setImmediate(self.handler);
                    }
                },
            },
        });
        this.view.setOnClickListener(clickListener.$new());
    }
    updateView() {
    }
    setLabel(label) {
        this.label = label;
        if (!this.view) {
            console.warn(`[Button:${this.id}] Cannot set label - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const String = api_1.API.JString;
            this.view.setText(String.$new(label));
        });
    }
    onClick(handler) {
        this.handler = handler;
    }
}
exports.Button = Button;
