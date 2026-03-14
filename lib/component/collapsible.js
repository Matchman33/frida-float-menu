import { API } from "../api";
import { UIComponent } from "./ui-components";
import { applyStyle, dp } from "./style/style";
import { Logger } from "../logger";
export class Collapsible extends UIComponent {
    constructor(id, title, expanded = false) {
        super(id);
        this.pendingChildren = [];
        this.title = title;
        this.expanded = expanded;
        this.value = expanded;
    }
    createView(context) {
        const LinearLayout = API.LinearLayout;
        const TextView = API.TextView;
        const String = API.JString;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const LinearLayoutParams = API.LinearLayoutParams;
        const View = API.View;
        const Gravity = API.Gravity;
        const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
        const createRoundedCard = (bgColor, cornerDp, strokeColor, strokeDp) => {
            const drawable = GradientDrawable.$new();
            drawable.setShape(GradientDrawable.RECTANGLE.value);
            drawable.setColor(bgColor | 0);
            drawable.setCornerRadius(dp(context, cornerDp));
            drawable.setStroke(dp(context, strokeDp), strokeColor | 0);
            return drawable;
        };
        const container = LinearLayout.$new(context);
        container.setOrientation(LinearLayout.VERTICAL.value);
        container.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        const theme = this.menu.options.theme;
        const borderColor = theme.colors.divider;
        const cardBg = theme.colors.rowBg ?? theme.colors.cardBg;
        container.setBackground(createRoundedCard(cardBg, 10, borderColor, 1));
        container.setPadding(0, 0, 0, 0);
        container.setElevation(dp(context, 2));
        const titleRow = LinearLayout.$new(context);
        titleRow.setOrientation(LinearLayout.HORIZONTAL.value);
        titleRow.setGravity(Gravity.CENTER_VERTICAL.value);
        titleRow.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        titleRow.setPadding(dp(context, 14), dp(context, 12), dp(context, 14), dp(context, 12));
        titleRow.setMinimumHeight(dp(context, 48));
        const arrowText = this.expanded ? "⌃" : "›";
        const arrowTextView = TextView.$new(context);
        arrowTextView.setText(String.$new(arrowText));
        arrowTextView.setSingleLine(true);
        arrowTextView.setTextColor(theme.colors.subText);
        arrowTextView.setTextSize(2, 20);
        arrowTextView.setGravity(Gravity.CENTER.value);
        arrowTextView.setPadding(dp(context, 12), 0, 0, 0);
        this.arrowView = arrowTextView;
        const titleView = TextView.$new(context);
        titleView.setText(String.$new(this.title));
        titleView.setSingleLine(true);
        applyStyle(titleView, "text", this.menu.options.theme);
        titleView.setTypeface(null, 1);
        titleView.setTextSize(2, 16);
        titleView.setLayoutParams(LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0));
        titleRow.addView(titleView);
        titleRow.addView(this.arrowView);
        const divider = View.$new(context);
        divider.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, dp(context, 1)));
        divider.setBackgroundColor(borderColor);
        if (!this.expanded) {
            divider.setVisibility(View.GONE.value);
        }
        this.contentContainer = LinearLayout.$new(context);
        this.contentContainer.setOrientation(LinearLayout.VERTICAL.value);
        const lp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
        this.contentContainer.setLayoutParams(lp);
        this.contentContainer.setPadding(dp(context, 10), dp(context, 10), dp(context, 10), dp(context, 10));
        if (this.expanded) {
            this.contentContainer.setVisibility(View.VISIBLE.value);
        }
        else {
            this.contentContainer.setVisibility(View.GONE.value);
        }
        container.addView(titleRow);
        container.addView(divider);
        container.addView(this.contentContainer);
        this.view = container;
        if (this.pendingChildren.length > 0) {
            const ctx = this.view.getContext();
            for (const c of this.pendingChildren) {
                try {
                    this.menu.uiComponents.set(c.getId(), c);
                    c.setMenu(this.menu);
                    c.init(ctx);
                    const v = this.menu.prepareComponentView(ctx, c);
                    if (v)
                        this.contentContainer.addView(v);
                    this.menu.bindComponentEvents(c);
                }
                catch (e) {
                    Logger.instance.error(`[Collapsible:${this.id}] addChild: ${c.getId()} - ${e}`);
                }
            }
            this.pendingChildren = [];
        }
        this.view.titleRow = titleRow;
        this.view.titleView = titleView;
        this.view.contentContainer = this.contentContainer;
        this.view.divider = divider;
        const OnClickListener = API.OnClickListener;
        const self = this;
        const clickListener = Java.registerClass({
            name: "com.frida.CollapsibleClickListener" +
                Date.now() +
                Math.random().toString(36).substring(4),
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
            Logger.instance.warn(`[Collapsible:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        this.expanded = this.value;
        Java.scheduleOnMainThread(() => {
            const View = API.View;
            const String = API.JString;
            const contentContainer = this.view.contentContainer;
            const divider = this.view.divider;
            if (contentContainer) {
                contentContainer.setVisibility(this.expanded ? View.VISIBLE.value : View.GONE.value);
            }
            if (divider) {
                divider.setVisibility(this.expanded ? View.VISIBLE.value : View.GONE.value);
            }
            if (this.arrowView) {
                const arrowText = this.expanded ? "⌃" : "›";
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
            Logger.instance.warn(`[Collapsible:${this.id}] Cannot set title - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const titleView = this.view.titleView;
            if (titleView) {
                const String = API.JString;
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
                const v = this.menu.prepareComponentView(ctx, component);
                if (v)
                    this.contentContainer.addView(v);
                this.menu.bindComponentEvents(component);
            }
            catch (e) {
                Logger.instance.error(`[Collapsible:${this.id}] addChild error: ${e}`);
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
