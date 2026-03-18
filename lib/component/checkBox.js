import Java from "frida-java-bridge";
import { API } from "../api.js";
import { Logger } from "../logger.js";
import { applyStyle, dp } from "./style/style.js";
import { UIComponent } from "./ui-components.js";
export class CheckBoxGroup extends UIComponent {
    constructor(id, title, options, initialChecked = []) {
        super(id);
        this.optionsMap = new Map();
        this.maxDisplayCount = 3;
        this.title = title;
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
        const LinearLayout = API.LinearLayout;
        const LinearLayoutParams = API.LinearLayoutParams;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const TextView = API.TextView;
        const Gravity = API.Gravity;
        const String = API.JString;
        const OnClickListener = API.OnClickListener;
        const theme = this.menu.options.theme;
        const root = LinearLayout.$new(context);
        root.setOrientation(LinearLayout.VERTICAL.value);
        root.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        const titleView = TextView.$new(context);
        titleView.setText(String.$new(this.title));
        applyStyle(titleView, "caption", theme);
        try {
            titleView.setTypeface(null, 1);
        }
        catch (_e) { }
        try {
            titleView.setAllCaps(true);
        }
        catch (_e) { }
        try {
            titleView.setLetterSpacing(0.04);
        }
        catch (_e) { }
        const titleLp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
        titleLp.setMargins(0, 0, 0, dp(context, 8));
        titleView.setLayoutParams(titleLp);
        const triggerRow = LinearLayout.$new(context);
        triggerRow.setOrientation(LinearLayout.HORIZONTAL.value);
        triggerRow.setGravity(Gravity.CENTER_VERTICAL.value);
        applyStyle(triggerRow, "row", theme);
        triggerRow.setPadding(dp(context, 14), dp(context, 14), dp(context, 14), dp(context, 14));
        const valueView = TextView.$new(context);
        valueView.setText(String.$new(this.getDisplayText()));
        applyStyle(valueView, "text", theme);
        valueView.setTextSize(2, 14);
        try {
            valueView.setTypeface(null, 1);
        }
        catch (_e) { }
        valueView.setSingleLine(true);
        valueView.setGravity(Gravity.LEFT.value | Gravity.CENTER_VERTICAL.value);
        valueView.setLayoutParams(LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0));
        const arrowView = TextView.$new(context);
        arrowView.setText(String.$new("⌄"));
        arrowView.setTextColor(theme.colors.accent);
        arrowView.setTextSize(2, 18);
        try {
            arrowView.setTypeface(null, 1);
        }
        catch (_e) { }
        arrowView.setGravity(Gravity.CENTER.value);
        const arrowLp = LinearLayoutParams.$new(ViewGroupLayoutParams.WRAP_CONTENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
        arrowLp.leftMargin = dp(context, 12);
        arrowView.setLayoutParams(arrowLp);
        triggerRow.addView(valueView);
        triggerRow.addView(arrowView);
        const self = this;
        const clickListener = Java.registerClass({
            name: "com.frida.MultiSelectTriggerClick" +
                Date.now() +
                Math.random().toString(36).slice(2),
            implements: [OnClickListener],
            methods: {
                onClick: function () {
                    self.openMultiSelectDialog(context);
                },
            },
        });
        triggerRow.setClickable(true);
        triggerRow.setOnClickListener(clickListener.$new());
        root.addView(titleView);
        root.addView(triggerRow);
        this.view = root;
        this.titleView = titleView;
        this.valueView = valueView;
        this.arrowView = arrowView;
        this.triggerRow = triggerRow;
    }
    openMultiSelectDialog(context) {
        const AlertDialogBuilder = API.AlertDialogBuilder;
        const String = API.JString;
        const opts = Array.from(this.optionsMap.values());
        const labels = opts.map((o) => o.label);
        const checkedArr = opts.map((o) => !!o.checked);
        const csArray = Java.array("java.lang.CharSequence", labels.map((s) => String.$new(s)));
        const boolArray = Java.array("boolean", checkedArr);
        const DialogMultiChoiceListener = API.DialogMultiChoiceListener;
        const DialogClickListener = API.DialogClickListener;
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
                    if (self.changeHandler) {
                        setImmediate(() => self.changeHandler(self.value, {
                            id: opt.id,
                            checked: isChecked,
                        }));
                    }
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
                    if (self.valueChangeHandler) {
                        setImmediate(() => self.valueChangeHandler(self.value));
                    }
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
        builder.setTitle(String.$new(this.title || "请选择"));
        builder.setMultiChoiceItems(csArray, boolArray, multiListener.$new());
        builder.setPositiveButton(String.$new("确定"), okListener.$new());
        builder.setNegativeButton(String.$new("取消"), cancelListener.$new());
        const dialog = builder.create();
        const WindowManagerLP = API.LayoutParams;
        const BuildVERSION = API.BuildVERSION;
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
        if (!this.valueView)
            return;
        Java.scheduleOnMainThread(() => {
            const String = API.JString;
            this.valueView.setText(String.$new(this.getDisplayText()));
        });
    }
    getDisplayText() {
        const selected = this.getCheckedValues();
        if (selected.length === 0) {
            return `请选择`;
        }
        const labels = selected.map((x) => x.label);
        if (labels.length <= this.maxDisplayCount) {
            return `${labels.join("、")}`;
        }
        const shown = labels.slice(0, this.maxDisplayCount).join("、");
        const rest = labels.length - this.maxDisplayCount;
        return `${shown} +${rest}`;
    }
    getCheckedValues() {
        return Array.from(this.optionsMap.values()).filter((op) => op.checked);
    }
    setChecked(id, checked) {
        if (!this.optionsMap.has(id)) {
            Logger.instance.warn(`[CheckBoxGroup:${this.id}] Option with id "${id}" not found`);
            return;
        }
        const opt = this.optionsMap.get(id);
        this.optionsMap.set(id, { ...opt, checked });
        this.value = this.getCheckedValues();
        this.updateView();
        this.emit("change", this.value, { id, checked });
        this.emit("valueChanged", this.value);
        if (this.changeHandler) {
            this.changeHandler(this.value, { id: opt.id, checked });
        }
        if (this.valueChangeHandler) {
            this.valueChangeHandler(this.value);
        }
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
    setTitle(title) {
        this.title = title;
        if (!this.titleView)
            return;
        Java.scheduleOnMainThread(() => {
            const String = API.JString;
            this.titleView.setText(String.$new(title));
            this.updateView();
        });
    }
}
