import { API } from "../api";
import { Logger } from "../logger";
import { applyStyle, dp } from "./style/style";
import { UIComponent } from "./ui-components";
export class NumberInput extends UIComponent {
    constructor(id, initialValue = 0, min = null, max = null, text = "单击输入数值", hint = "请输入数值", title = "请输入") {
        super(id);
        this.isShowDialog = false;
        this.value = initialValue;
        this.text = text;
        this.hint = hint;
        this.min = min;
        this.max = max;
        this.title = title;
    }
    updateView() {
        if (!this.view) {
            Logger.instance.warn(`[Switch:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const String = API.JString;
            this.view.setText(String.$new(`${this.text}: ${this.value}`));
        });
    }
    getValue() {
        return this.value;
    }
    createView(context) {
        const Button = API.Button;
        const String = API.JString;
        this.view = Button.$new(context);
        this.view.setText(String.$new(`${this.text}: ${this.value}`));
        applyStyle(this.view, "inputTrigger", this.menu.options.theme);
        const self = this;
        this.view.setOnClickListener(Java.registerClass({
            name: "com.frida.NumberInputClick" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [API.OnClickListener],
            methods: {
                onClick: function (v) {
                    if (self.isShowDialog)
                        return;
                    self.isShowDialog = true;
                    self.showDialog(context);
                },
            },
        }).$new());
    }
    showDialog(context) {
        Java.scheduleOnMainThread(() => {
            const AlertDialogBuilder = API.AlertDialogBuilder;
            const EditText = API.EditText;
            const String = API.JString;
            const TextViewBufferType = API.TextViewBufferType;
            const InputType = API.InputType;
            const LayoutParams = API.LayoutParams;
            const LinearLayoutParams = API.LinearLayoutParams;
            const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
            const builder = AlertDialogBuilder.$new(context);
            builder.setTitle(String.$new(this.title));
            const input = EditText.$new(context);
            input.setHint(String.$new(this.hint));
            input.setText(String.$new(this.value + ""), TextViewBufferType.NORMAL.value);
            input.setInputType(InputType.TYPE_CLASS_NUMBER.value |
                InputType.TYPE_NUMBER_FLAG_DECIMAL.value |
                InputType.TYPE_NUMBER_FLAG_SIGNED.value);
            const lp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
            input.setLayoutParams(lp);
            const LinearLayout = API.LinearLayout;
            const container = LinearLayout.$new(context);
            container.setPadding(dp(context, 16), dp(context, 10), dp(context, 16), dp(context, 6));
            container.addView(input);
            builder.setView(container);
            const self = this;
            builder.setPositiveButton(String.$new("确认"), Java.registerClass({
                name: "com.frida.NumberInputOK" +
                    Date.now() +
                    Math.random().toString(36).substring(6),
                implements: [API.DialogInterfaceOnClickListener],
                methods: {
                    onClick: function (_dialog, _which) {
                        self.isShowDialog = false;
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
            builder.setNegativeButton(String.$new("取消"), Java.registerClass({
                name: "com.frida.AlertTextInputCancel" +
                    Date.now() +
                    Math.random().toString(36).substring(6),
                implements: [API.DialogInterfaceOnClickListener],
                methods: {
                    onClick: function (dialog, which) {
                        self.isShowDialog = false;
                    },
                },
            }).$new());
            const dialog = builder.create();
            const window = dialog.getWindow();
            const BuildVERSION = API.BuildVERSION;
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
                const bg = API.GradientDrawable.$new();
                bg.setColor(this.menu.options.theme.colors.cardBg);
                bg.setCornerRadius(dp(context, 14));
                bg.setStroke(dp(context, 1), this.menu.options.theme.colors.divider);
                const win = dialog.getWindow();
                if (win) {
                    const decor = win.getDecorView();
                    decor.setBackground(bg);
                    decor.setPadding(dp(context, 12), dp(context, 12), dp(context, 12), dp(context, 12));
                }
                const AlertDialog = API.AlertDialog;
                const ad = Java.cast(dialog, AlertDialog);
                const BUTTON_POSITIVE = -1;
                const BUTTON_NEGATIVE = -2;
                const pos = ad.getButton(BUTTON_POSITIVE);
                const neg = ad.getButton(BUTTON_NEGATIVE);
                if (pos) {
                    pos.setAllCaps(false);
                    pos.setTextColor(this.menu.options.theme.colors.accent);
                    pos.setPadding(dp(context, 10), dp(context, 8), dp(context, 10), dp(context, 8));
                }
                if (neg) {
                    neg.setAllCaps(false);
                    neg.setTextColor(this.menu.options.theme.colors.subText);
                    neg.setPadding(dp(context, 10), dp(context, 8), dp(context, 10), dp(context, 8));
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
                        const TextView = API.TextView;
                        const t = Java.cast(tv, TextView);
                        t.setTextColor(this.menu.options.theme.colors.text);
                    }
                }
            }
            catch (e) {
                Logger.instance.error(e);
            }
        });
    }
    onValueChange(handler) {
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
export class TextInput extends UIComponent {
    constructor(id, initialValue = "", text = "单击输入文本", hint = "请输入文本", title = "请输入") {
        super(id);
        this.isShowDialog = false;
        this.text = text;
        this.hint = hint;
        this.value = initialValue;
        this.title = title;
    }
    updateView() {
        if (!this.view) {
            Logger.instance.warn(`[Switch:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const String = API.JString;
            this.view.setText(String.$new(`${this.text}: ${this.value}`));
        });
    }
    createView(context) {
        const Button = API.Button;
        const String = API.JString;
        this.view = Button.$new(context);
        applyStyle(this.view, "inputTrigger", this.menu.options.theme);
        this.view.setText(String.$new(`${this.text}: ${this.value}`));
        const self = this;
        this.view.setOnClickListener(Java.registerClass({
            name: "com.frida.AlertTextInputClick" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [API.OnClickListener],
            methods: {
                onClick: function (v) {
                    if (self.isShowDialog)
                        return;
                    self.isShowDialog = true;
                    self.showDialog(context);
                },
            },
        }).$new());
    }
    emitValue(value) {
        this.emit("valueChanged", value);
    }
    onValueChange(handler) {
        this.handler = handler;
    }
    showDialog(context) {
        Java.scheduleOnMainThread(() => {
            const AlertDialogBuilder = API.AlertDialogBuilder;
            const EditText = API.EditText;
            const String = API.JString;
            const TextViewBufferType = API.TextViewBufferType;
            const builder = AlertDialogBuilder.$new(context);
            const LinearLayoutParams = API.LinearLayoutParams;
            const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
            const input = EditText.$new(context);
            const LinearLayout = API.LinearLayout;
            input.setHint(String.$new(this.hint));
            input.setText(String.$new(this.value), TextViewBufferType.NORMAL.value);
            builder.setTitle(String.$new(this.title));
            const lp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
            input.setLayoutParams(lp);
            const container = LinearLayout.$new(context);
            container.setPadding(dp(context, 16), dp(context, 10), dp(context, 16), dp(context, 6));
            container.addView(input);
            builder.setView(container);
            const self = this;
            builder.setPositiveButton(String.$new("确认"), Java.registerClass({
                name: "com.frida.AlertTextInputOK" +
                    Date.now() +
                    Math.random().toString(36).substring(6),
                implements: [API.DialogInterfaceOnClickListener],
                methods: {
                    onClick: function (dialog, which) {
                        self.isShowDialog = false;
                        const text = Java.cast(input.getText(), Java.use("java.lang.CharSequence")).toString() + "";
                        self.value = text.trim();
                        self.view.setText(String.$new(`${self.text}: ${self.value}`));
                        self.emit("valueChanged", text);
                        if (self.handler)
                            self.handler(text);
                    },
                },
            }).$new());
            builder.setNegativeButton(String.$new("取消"), Java.registerClass({
                name: "com.frida.AlertTextInputCancel" +
                    Date.now() +
                    Math.random().toString(36).substring(6),
                implements: [API.DialogInterfaceOnClickListener],
                methods: {
                    onClick: function (dialog, which) {
                        self.isShowDialog = false;
                    },
                },
            }).$new());
            const LayoutParams = API.LayoutParams;
            const dialog = builder.create();
            const bg = API.GradientDrawable.$new();
            bg.setColor(this.menu.options.theme.colors.cardBg);
            bg.setCornerRadius(dp(context, 14));
            bg.setStroke(dp(context, 1), this.menu.options.theme.colors.divider);
            const window = dialog.getWindow();
            const BuildVERSION = API.BuildVERSION;
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
                decor.setPadding(dp(context, 12), dp(context, 12), dp(context, 12), dp(context, 12));
            }
            catch (e) {
                Logger.instance.error(e);
            }
            try {
                const AlertDialog = API.AlertDialog;
                const ad = Java.cast(dialog, AlertDialog);
                const BUTTON_POSITIVE = -1;
                const BUTTON_NEGATIVE = -2;
                const pos = ad.getButton(BUTTON_POSITIVE);
                const neg = ad.getButton(BUTTON_NEGATIVE);
                if (pos) {
                    pos.setAllCaps(false);
                    pos.setTextColor(this.menu.options.theme.colors.accent);
                    pos.setPadding(dp(context, 10), dp(context, 8), dp(context, 10), dp(context, 8));
                }
                if (neg) {
                    neg.setAllCaps(false);
                    neg.setTextColor(this.menu.options.theme.colors.subText);
                    neg.setPadding(dp(context, 10), dp(context, 8), dp(context, 10), dp(context, 8));
                }
            }
            catch (e) {
                Logger.instance.error(e);
            }
            try {
                const titleId = context
                    .getResources()
                    .getIdentifier(Java.use("java.lang.String").$new("alertTitle"), Java.use("java.lang.String").$new("id"), Java.use("java.lang.String").$new("android"));
                if (titleId && titleId !== 0) {
                    const tv = dialog.findViewById(titleId);
                    if (tv) {
                        const TextView = API.TextView;
                        const t = Java.cast(tv, TextView);
                        t.setTextColor(this.menu.options.theme.colors.text);
                    }
                }
            }
            catch (e) {
                Logger.instance.error(e);
            }
        });
    }
    setText(text) {
        if (this.view) {
            Java.scheduleOnMainThread(() => {
                const String = API.JString;
                this.view.setText(String.$new(text));
            });
        }
    }
}
