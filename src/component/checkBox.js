"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.CheckBoxGroup = void 0;
const api_1 = require("../api");
const style_1 = require("./style/style");
const ui_components_1 = require("./ui-components");
class CheckBoxGroup extends ui_components_1.UIComponent {
    constructor(id, options, initialChecked = [], _columns = 3) {
        super(id);
        this.optionsMap = new Map();
        this.maxDisplayCount = 3;
        for (const opt of options) {
            const checked = initialChecked.includes(opt.id);
            this.optionsMap.set(opt.id, { ...opt, checked });
        }
        this.value = this.getCheckedValues();
    }
    onChangeHandler(handler) {
        this.changeHandler = handler;
    }
    onValueChangeHandler(handler) {
        this.valueChangeHandler = handler;
    }
    setMaxDisplayCount(n) {
        this.maxDisplayCount = Math.max(1, n);
        this.updateView();
    }
    createView(context) {
        const LinearLayout = api_1.API.LinearLayout;
        const TextView = api_1.API.TextView;
        const String = api_1.API.JString;
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
        const Gravity = api_1.API.Gravity;
        const root = LinearLayout.$new(context);
        root.setOrientation(LinearLayout.VERTICAL.value);
        root.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        const trigger = TextView.$new(context);
        trigger.setGravity(Gravity.CENTER_VERTICAL.value);
        trigger.setSingleLine(true);
        (0, style_1.applyStyle)(trigger, "inputTrigger", this.menu.options.theme);
        trigger.setText(String.$new(this.buildDisplayText() + "  ▾"));
        const ViewOnClickListener = api_1.API.OnClickListener;
        const self = this;
        const clickListener = Java.registerClass({
            name: "com.frida.MultiSelectTriggerClick" +
                Date.now() +
                Math.random().toString(36).slice(2),
            implements: [ViewOnClickListener],
            methods: {
                onClick: function () {
                    self.openMultiSelectDialog(context);
                },
            },
        });
        trigger.setOnClickListener(clickListener.$new());
        root.addView(trigger);
        this.view = root;
        this.triggerText = trigger;
    }
    openMultiSelectDialog(context) {
        const AlertDialogBuilder = api_1.API.AlertDialogBuilder;
        const String = api_1.API.JString;
        const opts = Array.from(this.optionsMap.values());
        const labels = opts.map((o) => o.label);
        const checkedArr = opts.map((o) => !!o.checked);
        const csArray = Java.array("java.lang.CharSequence", labels.map((s) => String.$new(s)));
        const boolArray = Java.array("boolean", checkedArr);
        const DialogMultiChoiceListener = api_1.API.DialogMultiChoiceListener;
        const DialogClickListener = api_1.API.DialogClickListener;
        const self = this;
        const multiListener = Java.registerClass({
            name: "com.frida.MultiChoiceListener" +
                Date.now() +
                Math.random().toString(36).slice(2),
            implements: [DialogMultiChoiceListener],
            methods: {
                onClick: function (_dialog, which, isChecked) {
                    const opt = opts[which];
                    self.optionsMap.set(opt.id, { ...opt, checked: isChecked });
                    self.value = self.getCheckedValues();
                    self.emit("change", self.value, { id: opt.id, checked: isChecked });
                    if (self.changeHandler)
                        setImmediate(() => self.changeHandler(self.value, {
                            id: opt.id,
                            checked: isChecked,
                        }));
                },
            },
        });
        const okListener = Java.registerClass({
            name: "com.frida.MultiChoiceOk" +
                Date.now() +
                Math.random().toString(36).slice(2),
            implements: [DialogClickListener],
            methods: {
                onClick: function (dialog, _which) {
                    self.value = self.getCheckedValues();
                    self.updateView();
                    self.emit("valueChanged", self.value);
                    if (self.valueChangeHandler)
                        setImmediate(() => self.valueChangeHandler(self.value));
                    dialog.dismiss();
                },
            },
        });
        const cancelListener = Java.registerClass({
            name: "com.frida.MultiChoiceCancel" +
                Date.now() +
                Math.random().toString(36).slice(2),
            implements: [DialogClickListener],
            methods: {
                onClick: function (dialog, _which) {
                    dialog.dismiss();
                },
            },
        });
        const builder = AlertDialogBuilder.$new(context);
        builder.setTitle(String.$new("请选择"));
        builder.setMultiChoiceItems(csArray, boolArray, multiListener.$new());
        builder.setPositiveButton(String.$new("确定"), okListener.$new());
        builder.setNegativeButton(String.$new("取消"), cancelListener.$new());
        const dialog = builder.create();
        const WindowManagerLP = api_1.API.LayoutParams;
        const BuildVERSION = api_1.API.BuildVERSION;
        const win = dialog.getWindow();
        if (win) {
            if (BuildVERSION.SDK_INT.value >= 26) {
                win.setType(WindowManagerLP.TYPE_APPLICATION_OVERLAY.value);
            }
            else {
                win.setType(WindowManagerLP.TYPE_PHONE.value);
            }
            win.addFlags(WindowManagerLP.FLAG_NOT_FOCUSABLE.value);
            win.addFlags(WindowManagerLP.FLAG_NOT_TOUCH_MODAL.value);
        }
        dialog.show();
    }
    updateView() {
        if (!this.triggerText)
            return;
        Java.scheduleOnMainThread(() => {
            const String = api_1.API.JString;
            this.triggerText.setText(String.$new(this.buildDisplayText() + "  ▾"));
        });
    }
    buildDisplayText() {
        const selected = this.getCheckedValues();
        if (selected.length === 0)
            return "请选择";
        const labels = selected.map((x) => x.label);
        if (labels.length <= this.maxDisplayCount)
            return labels.join("、");
        const shown = labels.slice(0, this.maxDisplayCount).join("、");
        const rest = labels.length - this.maxDisplayCount;
        return `${shown} +${rest}`;
    }
    getCheckedValues() {
        return Array.from(this.optionsMap.values()).filter((op) => op.checked);
    }
    setChecked(id, checked) {
        if (!this.optionsMap.has(id)) {
            console.warn(`[CheckBoxGroup:${this.id}] Option with id "${id}" not found`);
            return;
        }
        const opt = this.optionsMap.get(id);
        this.optionsMap.set(id, { ...opt, checked });
        this.value = this.getCheckedValues();
        this.updateView();
        this.emit("change", this.value, { id, checked });
        this.emit("valueChanged", this.value);
        if (this.changeHandler)
            this.changeHandler(this.value, { id: opt.id, checked });
        if (this.valueChangeHandler)
            this.valueChangeHandler(this.value);
    }
    setCheckedValues(checkedIds) {
        for (const [id, opt] of this.optionsMap.entries()) {
            this.optionsMap.set(id, { ...opt, checked: false });
        }
        for (const id of checkedIds) {
            if (this.optionsMap.has(id)) {
                const opt = this.optionsMap.get(id);
                this.optionsMap.set(id, { ...opt, checked: true });
            }
        }
        this.value = this.getCheckedValues();
        this.updateView();
        this.emit("change", this.value);
        this.emit("valueChanged", this.value);
        if (this.changeHandler)
            this.changeHandler(this.value);
        if (this.valueChangeHandler)
            this.valueChangeHandler(this.value);
    }
    getOptions() {
        return Array.from(this.optionsMap.values()).slice();
    }
}
exports.CheckBoxGroup = CheckBoxGroup;
