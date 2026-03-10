"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Switch = void 0;
const api_1 = require("../api");
const style_1 = require("./style/style");
const ui_components_1 = require("./ui-components");
class Switch extends ui_components_1.UIComponent {
    onValueChange(handler) {
        this.handler = handler;
    }
    constructor(id, label, initialValue = false, handler) {
        super(id);
        this.label = label;
        this.value = initialValue;
        this.handler = handler;
    }
    createView(context) {
        const LinearLayout = api_1.API.LinearLayout;
        const LinearLayoutParams = api_1.API.LinearLayoutParams;
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
        const Gravity = api_1.API.Gravity;
        const TextView = api_1.API.TextView;
        const Switch = api_1.API.Switch;
        const String = api_1.API.JString;
        const row = LinearLayout.$new(context);
        row.setOrientation(LinearLayout.HORIZONTAL.value);
        row.setGravity(Gravity.CENTER_VERTICAL.value);
        (0, style_1.applyStyle)(row, "row", this.menu.options.theme);
        const label = TextView.$new(context);
        label.setText(String.$new(this.label));
        (0, style_1.applyStyle)(label, "text", this.menu.options.theme);
        label.setLayoutParams(LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1));
        const sw = Switch.$new(context);
        sw.setChecked(this.value);
        sw.setText(String.$new(""));
        row.addView(label);
        row.addView(sw);
        this.view = row;
        this.switchView = sw;
        this.labelView = label;
        const Listener = api_1.API.CompoundButtonOnCheckedChangeListener;
        const self = this;
        const changeListener = Java.registerClass({
            name: "com.frida.MyCheckedChangeListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [Listener],
            methods: {
                onCheckedChanged: function (_btn, isChecked) {
                    self.value = isChecked;
                    self.emit("valueChanged", isChecked);
                    if (self.handler)
                        setImmediate(() => self.handler(isChecked));
                },
            },
        });
        this.switchView.setOnCheckedChangeListener(changeListener.$new());
    }
    updateView() {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => {
            if (this.switchView)
                this.switchView.setChecked(this.value);
        });
    }
    setLabel(label) {
        this.label = label;
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => {
            const String = api_1.API.JString;
            if (this.labelView)
                this.labelView.setText(String.$new(label));
        });
    }
}
exports.Switch = Switch;
