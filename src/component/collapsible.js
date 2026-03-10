"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Collapsible = void 0;
const api_1 = require("../api");
const ui_components_1 = require("./ui-components");
const style_1 = require("./style/style");
class Collapsible extends ui_components_1.UIComponent {
    constructor(id, title, expanded = false) {
        super(id);
        this.pendingChildren = [];
        this.title = title;
        this.expanded = expanded;
        this.value = expanded;
    }
    createView(context) {
        const LinearLayout = api_1.API.LinearLayout;
        const TextView = api_1.API.TextView;
        const String = api_1.API.JString;
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
        const LinearLayoutParams = api_1.API.LinearLayoutParams;
        const View = api_1.API.View;
        const Gravity = api_1.API.Gravity;
        const container = LinearLayout.$new(context);
        container.setOrientation(LinearLayout.VERTICAL.value);
        container.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        (0, style_1.applyStyle)(container, "card", this.menu.options.theme);
        const titleRow = LinearLayout.$new(context);
        titleRow.setOrientation(LinearLayout.HORIZONTAL.value);
        titleRow.setGravity(Gravity.CENTER_VERTICAL.value);
        titleRow.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        (0, style_1.applyStyle)(titleRow, "row", this.menu.options.theme);
        const arrowText = this.expanded ? "▼" : "▶";
        const arrowTextView = TextView.$new(context);
        arrowTextView.setText(String.$new(arrowText));
        arrowTextView.setSingleLine(true);
        (0, style_1.applyStyle)(arrowTextView, "caption", this.menu.options.theme);
        arrowTextView.setPadding(0, 0, (0, style_1.dp)(context, 8), 0);
        this.arrowView = arrowTextView;
        const titleView = TextView.$new(context);
        titleView.setText(String.$new(this.title));
        titleView.setSingleLine(true);
        (0, style_1.applyStyle)(titleView, "text", this.menu.options.theme);
        titleView.setTypeface(null, 1);
        titleView.setLayoutParams(LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0));
        titleRow.addView(this.arrowView);
        titleRow.addView(titleView);
        this.contentContainer = LinearLayout.$new(context);
        this.contentContainer.setOrientation(LinearLayout.VERTICAL.value);
        this.contentContainer.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        this.contentContainer.setPadding((0, style_1.dp)(context, 2), (0, style_1.dp)(context, 2), (0, style_1.dp)(context, 2), (0, style_1.dp)(context, 4));
        if (this.expanded) {
            this.contentContainer.setVisibility(View.VISIBLE.value);
        }
        else {
            this.contentContainer.setVisibility(View.GONE.value);
        }
        container.addView(titleRow);
        container.addView(this.contentContainer);
        this.view = container;
        if (this.pendingChildren.length > 0) {
            const ctx = this.view.getContext();
            for (const c of this.pendingChildren) {
                try {
                    this.menu.uiComponents.set(c.getId(), c);
                    c.setMenu(this.menu);
                    c.init(ctx);
                    const v = c.getView();
                    if (v)
                        this.contentContainer.addView(v);
                }
                catch (e) {
                    console.error(`[Collapsible:${this.id}] addChild: ${c.getId()} - ${e}`);
                }
            }
            this.pendingChildren = [];
        }
        this.view.titleRow = titleRow;
        this.view.titleView = titleView;
        this.view.contentContainer = this.contentContainer;
        const OnClickListener = api_1.API.OnClickListener;
        const self = this;
        const clickListener = Java.registerClass({
            name: "com.frida.CollapsibleClickListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [OnClickListener],
            methods: {
                onClick: function () {
                    self.toggle();
                },
            },
        });
        titleRow.setOnClickListener(clickListener.$new());
    }
    updateView() {
        if (!this.view) {
            console.warn(`[Collapsible:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        this.expanded = this.value;
        Java.scheduleOnMainThread(() => {
            const View = api_1.API.View;
            const String = api_1.API.JString;
            const contentContainer = this.view.contentContainer;
            if (contentContainer) {
                contentContainer.setVisibility(this.expanded ? View.VISIBLE.value : View.GONE.value);
            }
            if (this.arrowView) {
                const arrowText = this.expanded ? "▼" : "▶";
                this.arrowView.setText(String.$new(arrowText));
            }
        });
    }
    toggle() {
        this.value = !this.value;
        this.updateView();
        this.emit("toggle", this.value);
    }
    expand() {
        this.value = true;
        this.updateView();
        this.emit("expand");
    }
    collapse() {
        this.value = false;
        this.updateView();
        this.emit("collapse");
    }
    setTitle(title) {
        this.title = title;
        if (!this.view) {
            console.warn(`[Collapsible:${this.id}] Cannot set title - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const titleView = this.view.titleView;
            if (titleView) {
                const String = api_1.API.JString;
                titleView.setText(String.$new(title));
            }
        });
    }
    addChild(component) {
        if (!this.contentContainer || !this.view) {
            this.pendingChildren.push(component);
            return;
        }
        Java.scheduleOnMainThread(() => {
            try {
                this.menu.uiComponents.set(component.getId(), component);
                component.setMenu(this.menu);
                const ctx = this.view.getContext();
                component.init(ctx);
                const v = component.getView();
                if (v)
                    this.contentContainer.addView(v);
            }
            catch (e) {
                console.error(`[Collapsible:${this.id}] addChild error: ${e}`);
            }
        });
    }
    addChildren(components) {
        for (const c of components)
            this.addChild(c);
    }
    removeChildView(view) {
        if (!this.contentContainer)
            return;
        Java.scheduleOnMainThread(() => {
            try {
                this.contentContainer.removeView(view);
            }
            catch (_e) { }
        });
    }
    clearChildren() {
        if (!this.contentContainer)
            return;
        Java.scheduleOnMainThread(() => {
            this.contentContainer.removeAllViews();
        });
    }
}
exports.Collapsible = Collapsible;
