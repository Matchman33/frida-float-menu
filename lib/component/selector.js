import { API } from "../api";
import { Logger } from "../logger";
import { applyStyle, dp } from "./style/style";
import { UIComponent } from "./ui-components";
export class Selector extends UIComponent {
    constructor(id, title, items, selectedIndex = 0, handler) {
        super(id);
        this.title = title;
        this.items = items ?? [];
        this.selectedIndex = Math.max(0, Math.min(selectedIndex, Math.max(0, this.items.length - 1)));
        this.value = this.items.length > 0 ? this.items[this.selectedIndex] : null;
        this.handler = handler;
    }
    getValue() {
        return this.value;
    }
    onValueChange(handler) {
        this.handler = handler;
    }
    createView(context) {
        this.context = context;
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
            name: "com.frida.MySelectorTriggerClickListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [OnClickListener],
            methods: {
                onClick: function (_v) {
                    self.showSelectDialog();
                },
            },
        });
        triggerRow.setClickable(true);
        triggerRow.setOnClickListener(clickListener.$new());
        root.addView(titleView);
        root.addView(triggerRow);
        this.titleView = titleView;
        this.valueView = valueView;
        this.view = root;
        this.refreshUi();
    }
    getSelectedLabel() {
        if (this.selectedIndex >= 0 &&
            this.selectedIndex < this.items.length &&
            this.items[this.selectedIndex]) {
            return this.items[this.selectedIndex].label ?? "";
        }
        return "";
    }
    getDisplayText() {
        const item = this.getSelectedLabel();
        if (!this.title && !item)
            return "";
        if (!this.title)
            return item;
        return `${item}`;
    }
    showSelectDialog() {
        if (!this.context || this.items.length === 0)
            return;
        Java.scheduleOnMainThread(() => {
            try {
                const AlertDialogBuilder = API.AlertDialogBuilder ?? Java.use("android.app.AlertDialog$Builder");
                const String = API.JString;
                const DialogInterfaceOnClickListener = API.DialogInterfaceOnClickListener ??
                    Java.use("android.content.DialogInterface$OnClickListener");
                const WindowManagerLayoutParams = Java.use("android.view.WindowManager$LayoutParams");
                const BuildVersion = Java.use("android.os.Build$VERSION");
                const labels = this.items.map((item) => String.$new(item.label));
                const javaItems = Java.array("java.lang.CharSequence", labels);
                const self = this;
                const itemClickListener = Java.registerClass({
                    name: "com.frida.MySelectorDialogClickListener" +
                        Date.now() +
                        Math.random().toString(36).substring(6),
                    implements: [DialogInterfaceOnClickListener],
                    methods: {
                        onClick: function (dialog, which) {
                            self.selectedIndex = which;
                            self.value = self.items[which];
                            self.refreshUi();
                            self.emit("valueChanged", self.value);
                            if (self.handler) {
                                setImmediate(() => self.handler(self.value));
                            }
                            try {
                                dialog.dismiss();
                            }
                            catch (_e) { }
                        },
                    },
                });
                const builder = AlertDialogBuilder.$new(this.context);
                builder.setTitle(String.$new(this.title));
                builder.setItems(javaItems, itemClickListener.$new());
                const dialog = builder.create();
                try {
                    const window = dialog.getWindow();
                    if (window) {
                        const sdkInt = BuildVersion.SDK_INT.value;
                        if (sdkInt >= 26) {
                            window.setType(WindowManagerLayoutParams.TYPE_APPLICATION_OVERLAY.value);
                        }
                        else {
                            window.setType(WindowManagerLayoutParams.TYPE_SYSTEM_ALERT.value);
                        }
                    }
                }
                catch (e) {
                    Logger.instance.warn(`[Selector:${this.id}] Failed to set dialog overlay type: ${e}`);
                }
                dialog.show();
                try {
                    const window = dialog.getWindow();
                    if (window) {
                        const dialogWidth = dp(this.context, 380);
                        window.setLayout(dialogWidth, WindowManagerLayoutParams.WRAP_CONTENT.value);
                    }
                }
                catch (e) {
                    Logger.instance.warn(`[Selector:${this.id}] Failed to resize dialog: ${e}`);
                }
            }
            catch (error) {
                Logger.instance.error(`[Selector:${this.id}] Failed to show selector dialog: ${error}`);
            }
        });
    }
    refreshUi() {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => {
            try {
                const String = API.JString;
                if (this.valueView) {
                    this.valueView.setText(String.$new(this.getDisplayText()));
                }
            }
            catch (error) {
                Logger.instance.error(`[Selector:${this.id}] Failed to refresh UI: ${error}`);
            }
        });
    }
    updateView() {
        if (!this.view) {
            Logger.instance.warn(`[Selector:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        const index = this.items.findIndex((value) => value && this.value && value.label == this.value.label);
        if (index !== -1) {
            this.selectedIndex = index;
        }
        this.refreshUi();
    }
    setItems(items) {
        this.items = items ?? [];
        if (this.items.length === 0) {
            this.selectedIndex = -1;
            this.value = null;
        }
        else {
            if (this.selectedIndex < 0 || this.selectedIndex >= this.items.length) {
                this.selectedIndex = 0;
            }
            this.value = this.items[this.selectedIndex];
        }
        this.refreshUi();
    }
    getSelectedIndex() {
        return this.selectedIndex;
    }
    setTitle(title) {
        this.title = title;
        if (!this.titleView)
            return;
        Java.scheduleOnMainThread(() => {
            const String = API.JString;
            this.titleView.setText(String.$new(title));
            this.refreshUi();
        });
    }
}
