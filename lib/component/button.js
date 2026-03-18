import Java from "frida-java-bridge";
import { API } from "../api.js";
import { Logger } from "../logger.js";
import { applyStyle } from "./style/style.js";
import { UIComponent } from "./ui-components.js";
export class Button extends UIComponent {
    constructor(id, label, kind = "primary", handler) {
        super(id);
        this.kind = "primary";
        this.label = label;
        this.kind = kind;
        this.handler = handler;
        this.value = null;
    }
    createView(context) {
        const Button = API.Button;
        const String = API.JString;
        const Gravity = API.Gravity;
        this.view = Button.$new(context);
        this.view.setText(String.$new(this.label));
        applyStyle(this.view, this.kind === "danger" ? "dangerButton" : "primaryButton", this.menu.options.theme);
        try {
            this.view.setGravity(Gravity.CENTER.value);
        }
        catch (_e) { }
        const OnClickListener = API.OnClickListener;
        const self = this;
        const clickListener = Java.registerClass({
            name: "com.frida.MyClickListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [OnClickListener],
            methods: {
                onClick: function (_v) {
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
            Logger.instance.warn(`[Button:${this.id}] Cannot set label - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const String = API.JString;
            this.view.setText(String.$new(label));
        });
    }
    onClick(handler) {
        this.handler = handler;
    }
}
