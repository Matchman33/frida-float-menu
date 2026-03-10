"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TextInput = exports.NumberInput = void 0;
const api_1 = require("../api");
const style_1 = require("./style/style");
const ui_components_1 = require("./ui-components");
class NumberInput extends ui_components_1.UIComponent {
    constructor(id, initialValue = 0, min = null, max = null, text = "单击输入数值", hint = "请输入数值", title = "请输入") {
        super(id);
        this.value = initialValue;
        this.text = text;
        this.hint = hint;
        this.min = min;
        this.max = max;
        this.title = title;
    }
    updateView() {
        if (!this.view) {
            console.warn(`[Switch:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const String = api_1.API.JString;
            this.view.setText(String.$new(`${this.text}: ${this.value}`));
        });
    }
    getValue() {
        return this.value;
    }
    createView(context) {
        const Button = api_1.API.Button;
        const String = api_1.API.JString;
        this.view = Button.$new(context);
        this.view.setText(String.$new(`${this.text}: ${this.value}`));
        (0, style_1.applyStyle)(this.view, "inputTrigger", this.menu.options.theme);
        const self = this;
        this.view.setOnClickListener(Java.registerClass({
            name: "com.frida.NumberInputClick" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [api_1.API.OnClickListener],
            methods: {
                onClick: function (v) {
                    self.showDialog(context);
                },
            },
        }).$new());
    }
    showDialog(context) {
        Java.scheduleOnMainThread(() => {
            const AlertDialogBuilder = api_1.API.AlertDialogBuilder;
            const EditText = api_1.API.EditText;
            const String = api_1.API.JString;
            const TextViewBufferType = api_1.API.TextViewBufferType;
            const InputType = api_1.API.InputType;
            const LayoutParams = api_1.API.LayoutParams;
            const LinearLayoutParams = api_1.API.LinearLayoutParams;
            const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
            const builder = AlertDialogBuilder.$new(context);
            builder.setTitle(String.$new(this.title));
            const input = EditText.$new(context);
            (0, style_1.applyEditTextStyle)(input, this.menu.options.theme);
            input.setHint(String.$new(this.hint));
            input.setText(String.$new(this.value + ""), TextViewBufferType.NORMAL.value);
            input.setInputType(InputType.TYPE_CLASS_NUMBER.value |
                InputType.TYPE_NUMBER_FLAG_DECIMAL.value |
                InputType.TYPE_NUMBER_FLAG_SIGNED.value);
            const lp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
            input.setLayoutParams(lp);
            const LinearLayout = api_1.API.LinearLayout;
            const container = LinearLayout.$new(context);
            container.setPadding((0, style_1.dp)(context, 16), (0, style_1.dp)(context, 10), (0, style_1.dp)(context, 16), (0, style_1.dp)(context, 6));
            container.addView(input);
            builder.setView(container);
            const self = this;
            builder.setPositiveButton(String.$new("确认"), Java.registerClass({
                name: "com.frida.NumberInputOK" +
                    Date.now() +
                    Math.random().toString(36).substring(6),
                implements: [api_1.API.DialogInterfaceOnClickListener],
                methods: {
                    onClick: function (_dialog, _which) {
                        const text = Java.cast(input.getText(), Java.use("java.lang.CharSequence")).toString() + "";
                        if (text === "") {
                            self.value = 0;
                        }
                        else {
                            const num = parseFloat(text);
                            if (!isNaN(num))
                                self.value = num;
                            else
                                return;
                        }
                        self.applyConstraints();
                        self.view.setText(String.$new(`${self.text}: ${self.value}`));
                        self.emit("valueChanged", self.value);
                        if (self.handler)
                            self.handler(self.value);
                    },
                },
            }).$new());
            builder.setNegativeButton(String.$new("取消"), null);
            const dialog = builder.create();
            const window = dialog.getWindow();
            const BuildVERSION = api_1.API.BuildVERSION;
            if (window) {
                if (BuildVERSION.SDK_INT.value >= 26) {
                    window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value);
                }
                else {
                    window.setType(LayoutParams.TYPE_PHONE.value);
                }
            }
            dialog.show();
            try {
                const bg = api_1.API.GradientDrawable.$new();
                bg.setColor(this.menu.options.theme.colors.cardBg);
                bg.setCornerRadius((0, style_1.dp)(context, 14));
                bg.setStroke((0, style_1.dp)(context, 1), this.menu.options.theme.colors.divider);
                const win = dialog.getWindow();
                if (win) {
                    const decor = win.getDecorView();
                    decor.setBackground(bg);
                    decor.setPadding((0, style_1.dp)(context, 12), (0, style_1.dp)(context, 12), (0, style_1.dp)(context, 12), (0, style_1.dp)(context, 12));
                }
                const AlertDialog = api_1.API.AlertDialog;
                const ad = Java.cast(dialog, AlertDialog);
                const BUTTON_POSITIVE = -1;
                const BUTTON_NEGATIVE = -2;
                const pos = ad.getButton(BUTTON_POSITIVE);
                const neg = ad.getButton(BUTTON_NEGATIVE);
                if (pos) {
                    pos.setAllCaps(false);
                    pos.setTextColor(this.menu.options.theme.colors.accent);
                    pos.setPadding((0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8), (0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8));
                }
                if (neg) {
                    neg.setAllCaps(false);
                    neg.setTextColor(this.menu.options.theme.colors.subText);
                    neg.setPadding((0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8), (0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8));
                }
            }
            catch (e) {
            }
            try {
                const titleId = context
                    .getResources()
                    .getIdentifier(Java.use("java.lang.String").$new("alertTitle"), Java.use("java.lang.String").$new("id"), Java.use("java.lang.String").$new("android"));
                if (titleId && titleId !== 0) {
                    const tv = dialog.findViewById(titleId);
                    if (tv) {
                        const TextView = api_1.API.TextView;
                        const t = Java.cast(tv, TextView);
                        t.setTextColor(this.menu.options.theme.colors.text);
                    }
                }
            }
            catch (e) {
                console.error(e);
            }
        });
    }
    setOnValueChange(handler) {
        this.handler = handler;
    }
    applyConstraints() {
        let constrained = this.value;
        if (this.min !== null)
            constrained = Math.max(this.min, constrained);
        if (this.max !== null)
            constrained = Math.min(this.max, constrained);
        this.value = constrained;
    }
    setHint(hint) {
        this.hint = hint;
    }
    setConstraints(min, max) {
        this.min = min;
        this.max = max;
        this.applyConstraints();
    }
    getNumber() {
        return this.value;
    }
    setNumber(value) {
        this.value = value;
        this.applyConstraints();
    }
}
exports.NumberInput = NumberInput;
class TextInput extends ui_components_1.UIComponent {
    constructor(id, initialValue = "", text = "单击输入文本", hint = "请输入文本", title = "请输入") {
        super(id);
        this.text = text;
        this.hint = hint;
        this.value = initialValue;
        this.title = title;
    }
    updateView() {
        if (!this.view) {
            console.warn(`[Switch:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const String = api_1.API.JString;
            this.view.setText(String.$new(`${this.text}: ${this.value}`));
        });
    }
    createView(context) {
        const Button = api_1.API.Button;
        const String = api_1.API.JString;
        this.view = Button.$new(context);
        (0, style_1.applyStyle)(this.view, "inputTrigger", this.menu.options.theme);
        this.view.setText(String.$new(`${this.text}: ${this.value}`));
        const self = this;
        this.view.setOnClickListener(Java.registerClass({
            name: "com.frida.AlertTextInputClick" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [api_1.API.OnClickListener],
            methods: {
                onClick: function (v) {
                    self.showDialog(context);
                },
            },
        }).$new());
    }
    emitValue(value) {
        this.emit("valueChanged", value);
    }
    setOnValueChange(handler) {
        this.handler = handler;
    }
    showDialog(context) {
        Java.scheduleOnMainThread(() => {
            const AlertDialogBuilder = api_1.API.AlertDialogBuilder;
            const EditText = api_1.API.EditText;
            const String = api_1.API.JString;
            const TextViewBufferType = api_1.API.TextViewBufferType;
            const builder = AlertDialogBuilder.$new(context);
            const LinearLayoutParams = api_1.API.LinearLayoutParams;
            const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
            const input = EditText.$new(context);
            const LinearLayout = api_1.API.LinearLayout;
            (0, style_1.applyEditTextStyle)(input, this.menu.options.theme);
            input.setHint(String.$new(this.hint));
            input.setText(String.$new(this.value), TextViewBufferType.NORMAL.value);
            builder.setTitle(String.$new(this.title));
            const lp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
            input.setLayoutParams(lp);
            const container = LinearLayout.$new(context);
            container.setPadding((0, style_1.dp)(context, 16), (0, style_1.dp)(context, 10), (0, style_1.dp)(context, 16), (0, style_1.dp)(context, 6));
            container.addView(input);
            builder.setView(container);
            const self = this;
            builder.setPositiveButton(String.$new("确认"), Java.registerClass({
                name: "com.frida.AlertTextInputOK" +
                    Date.now() +
                    Math.random().toString(36).substring(6),
                implements: [api_1.API.DialogInterfaceOnClickListener],
                methods: {
                    onClick: function (dialog, which) {
                        const text = Java.cast(input.getText(), Java.use("java.lang.CharSequence")).toString() + "";
                        self.value = text.trim();
                        self.view.setText(String.$new(`${self.text}: ${self.value}`));
                        self.emit("valueChanged", text);
                        if (self.handler)
                            self.handler(text);
                    },
                },
            }).$new());
            builder.setNegativeButton(String.$new("取消"), null);
            const LayoutParams = api_1.API.LayoutParams;
            const dialog = builder.create();
            const bg = api_1.API.GradientDrawable.$new();
            bg.setColor(this.menu.options.theme.colors.cardBg);
            bg.setCornerRadius((0, style_1.dp)(context, 14));
            bg.setStroke((0, style_1.dp)(context, 1), this.menu.options.theme.colors.divider);
            const window = dialog.getWindow();
            const BuildVERSION = api_1.API.BuildVERSION;
            if (window) {
                if (BuildVERSION.SDK_INT.value >= 26) {
                    window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value);
                }
                else {
                    window.setType(LayoutParams.TYPE_PHONE.value);
                }
            }
            dialog.show();
            try {
                const decor = dialog.getWindow().getDecorView();
                decor.setBackground(bg);
                decor.setPadding((0, style_1.dp)(context, 12), (0, style_1.dp)(context, 12), (0, style_1.dp)(context, 12), (0, style_1.dp)(context, 12));
            }
            catch (e) {
                console.error(e);
            }
            try {
                const AlertDialog = api_1.API.AlertDialog;
                const ad = Java.cast(dialog, AlertDialog);
                const BUTTON_POSITIVE = -1;
                const BUTTON_NEGATIVE = -2;
                const pos = ad.getButton(BUTTON_POSITIVE);
                const neg = ad.getButton(BUTTON_NEGATIVE);
                if (pos) {
                    pos.setAllCaps(false);
                    pos.setTextColor(this.menu.options.theme.colors.accent);
                    pos.setPadding((0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8), (0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8));
                }
                if (neg) {
                    neg.setAllCaps(false);
                    neg.setTextColor(this.menu.options.theme.colors.subText);
                    neg.setPadding((0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8), (0, style_1.dp)(context, 10), (0, style_1.dp)(context, 8));
                }
            }
            catch (e) {
                console.error(e);
            }
            try {
                const titleId = context
                    .getResources()
                    .getIdentifier(Java.use("java.lang.String").$new("alertTitle"), Java.use("java.lang.String").$new("id"), Java.use("java.lang.String").$new("android"));
                if (titleId && titleId !== 0) {
                    const tv = dialog.findViewById(titleId);
                    if (tv) {
                        const TextView = api_1.API.TextView;
                        const t = Java.cast(tv, TextView);
                        t.setTextColor(this.menu.options.theme.colors.text);
                    }
                }
            }
            catch (e) {
                console.error(e);
            }
        });
    }
    setText(text) {
        if (this.view) {
            Java.scheduleOnMainThread(() => {
                const String = api_1.API.JString;
                this.view.setText(String.$new(text));
            });
        }
    }
}
exports.TextInput = TextInput;
