"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TabsView = void 0;
const api_1 = require("../../api");
const event_emitter_1 = require("../../event-emitter");
const logger_1 = require("../../logger");
const style_1 = require("../style/style");
class TabsView {
    constructor(context, theme, initTabs, activeTabId) {
        this.tabs = new Map();
        this.logger = logger_1.Logger.instance;
        this.eventEmitter = new event_emitter_1.EventEmitter();
        this.context = context;
        this.theme = theme;
        this.initTabs = initTabs;
        this.activeTabId = activeTabId;
    }
    createTabView(parentView) {
        this.parentView = parentView;
        try {
            const LinearLayout = api_1.API.LinearLayout;
            const LinearLayoutParams = api_1.API.LinearLayoutParams;
            const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
            const TextView = api_1.API.TextView;
            const OnClickListener = api_1.API.OnClickListener;
            const JString = api_1.API.JString;
            const HorizontalScrollView = api_1.API.HorizontalScrollView;
            const GradientDrawable = api_1.API.GradientDrawable;
            const Gravity = api_1.API.Gravity;
            const self = this;
            const scrollView = HorizontalScrollView.$new(this.context);
            scrollView.setHorizontalScrollBarEnabled(false);
            scrollView.setScrollbarFadingEnabled(true);
            scrollView.setFillViewport(true);
            const scrollLp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
            scrollView.setLayoutParams(scrollLp);
            const bg = GradientDrawable.$new();
            bg.setCornerRadius((0, style_1.dp)(this.context, 14));
            bg.setColor(this.theme.colors.cardBg);
            bg.setStroke((0, style_1.dp)(this.context, 1), this.theme.colors.divider);
            scrollView.setBackgroundDrawable(bg);
            scrollView.setPadding((0, style_1.dp)(this.context, 8), (0, style_1.dp)(this.context, 6), (0, style_1.dp)(this.context, 8), (0, style_1.dp)(this.context, 6));
            const tabContainer = LinearLayout.$new(this.context);
            tabContainer.setOrientation(0);
            tabContainer.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.WRAP_CONTENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
            this.tabContainer = tabContainer;
            const styleTab = (tv, active) => {
                tv.setAllCaps(false);
                tv.setSingleLine(true);
                tv.setGravity(Gravity.CENTER.value);
                tv.setTextSize(2, this.theme.textSp.body);
                tv.setPadding((0, style_1.dp)(this.context, 12), (0, style_1.dp)(this.context, 8), (0, style_1.dp)(this.context, 12), (0, style_1.dp)(this.context, 8));
                const d = GradientDrawable.$new();
                d.setCornerRadius((0, style_1.dp)(this.context, 12));
                if (active) {
                    d.setColor(this.theme.colors.accent);
                    tv.setTextColor(0xffffffff | 0);
                }
                else {
                    d.setColor(0x00000000);
                    tv.setTextColor(this.theme.colors.subText);
                    d.setStroke((0, style_1.dp)(this.context, 1), this.theme.colors.divider);
                }
                tv.setBackgroundDrawable(d);
                try {
                    tv.setTypeface(null, active ? 1 : 0);
                }
                catch (e) { }
            };
            for (const [tabId, tabInfo] of this.tabs) {
                const tabText = TextView.$new(this.context);
                tabText.setText(JString.$new(tabInfo.label));
                const btnLp = LinearLayoutParams.$new(ViewGroupLayoutParams.WRAP_CONTENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
                btnLp.setMargins((0, style_1.dp)(this.context, 6), (0, style_1.dp)(this.context, 2), (0, style_1.dp)(this.context, 6), (0, style_1.dp)(this.context, 2));
                tabText.setLayoutParams(btnLp);
                styleTab(tabText, tabId === this.activeTabId);
                const tabClickListener = Java.registerClass({
                    name: "com.example.TabClickListener" +
                        Date.now() +
                        Math.random().toString(36).substring(6) +
                        "_" +
                        tabId,
                    implements: [OnClickListener],
                    methods: {
                        onClick: function () {
                            self.switchTab(tabId);
                        },
                    },
                });
                tabText.setOnClickListener(tabClickListener.$new());
                tabContainer.addView(tabText);
            }
            scrollView.addView(tabContainer);
            this.tabView = scrollView;
            parentView.addView(this.tabView);
            this.createTabContainer();
        }
        catch (error) {
            this.logger.error("Failed to create tab view: " + error);
        }
    }
    switchTab(tabId) {
        if (!this.tabs.has(tabId) || tabId === this.activeTabId)
            return;
        const oldTabId = this.activeTabId;
        this.activeTabId = tabId;
        this.refreshTabsUI();
        Java.scheduleOnMainThread(() => {
            try {
                const View = api_1.API.View;
                for (const [id, tabInfo] of this.tabs) {
                    const root = tabInfo.root;
                    if (!root)
                        continue;
                    if (id === tabId) {
                        root.setVisibility(View.VISIBLE.value);
                        this.currentContentContainer = tabInfo.container;
                        this.currentScrollView = tabInfo.scrollView;
                    }
                    else {
                        root.setVisibility(View.GONE.value);
                    }
                }
                if (this.tabContainer) {
                    const tabIds = Array.from(this.tabs.keys());
                    const childCount = this.tabContainer.getChildCount();
                    for (let i = 0; i < childCount && i < tabIds.length; i++) {
                        const tv = Java.cast(this.tabContainer.getChildAt(i), api_1.API.TextView);
                        this.updateTabStyle(tv, tabIds[i] === tabId);
                    }
                }
                this.eventEmitter.emit("tabChanged", tabId, oldTabId);
            }
            catch (error) {
                console.error(`Failed to switch to tab ${tabId}:`, error);
            }
        });
    }
    updateTabStyle(button, isActive) {
        const GradientDrawable = api_1.API.GradientDrawable;
        const ctx = button.getContext();
        const radius = (0, style_1.dp)(ctx, 12);
        const strokeW = (0, style_1.dp)(ctx, 1);
        const padH = (0, style_1.dp)(ctx, 12);
        const padV = (0, style_1.dp)(ctx, 8);
        try {
            button.setAllCaps(false);
        }
        catch (e) { }
        button.setSingleLine(true);
        button.setTextSize(2, this.theme.textSp.body);
        button.setPadding(padH, padV, padH, padV);
        const drawable = GradientDrawable.$new();
        drawable.setCornerRadius(radius);
        if (isActive) {
            drawable.setColor(this.theme.colors.accent);
            button.setTextColor(0xffffffff | 0);
            try {
                button.setTypeface(null, 1);
            }
            catch (e) { }
        }
        else {
            drawable.setColor(0x00000000);
            drawable.setStroke(strokeW, this.theme.colors.divider);
            button.setTextColor(this.theme.colors.subText);
            try {
                button.setTypeface(null, 0);
            }
            catch (e) { }
        }
        button.setBackgroundDrawable(drawable);
    }
    refreshTabsUI() {
        try {
            if (!this.tabContainer)
                return;
            const GradientDrawable = api_1.API.GradientDrawable;
            const count = this.tabContainer.getChildCount();
            const tabIds = Array.from(this.tabs.keys());
            for (let i = 0; i < count; i++) {
                const tv = this.tabContainer.getChildAt(i);
                const tabId = tabIds[i];
                const active = tabId === this.activeTabId;
                const d = GradientDrawable.$new();
                d.setCornerRadius((0, style_1.dp)(this.context, 12));
                if (active) {
                    d.setColor(this.theme.colors.accent);
                    tv.setTextColor(0xffffffff | 0);
                    try {
                        tv.setTypeface(null, 1);
                    }
                    catch (e) { }
                }
                else {
                    d.setColor(0x00000000);
                    d.setStroke((0, style_1.dp)(this.context, 1), this.theme.colors.divider);
                    tv.setTextColor(this.theme.colors.subText);
                    try {
                        tv.setTypeface(null, 0);
                    }
                    catch (e) { }
                }
                tv.setBackgroundDrawable(d);
            }
        }
        catch (e) { }
    }
    initializeTabs() {
        this.tabs.clear();
        if (this.initTabs && this.initTabs.length > 0) {
            for (const tabDef of this.initTabs) {
                this.tabs.set(tabDef.id, {
                    label: tabDef.label,
                    container: null,
                    components: new Set(),
                });
            }
            if (this.activeTabId && this.tabs.has(this.activeTabId)) {
                this.activeTabId = this.activeTabId;
            }
            else if (this.initTabs.length > 0) {
                this.activeTabId = this.initTabs[0].id;
            }
        }
        else {
            this.tabs.set("default", {
                label: "Default",
                container: null,
                components: new Set(),
            });
            this.activeTabId = "default";
        }
    }
    createTabContainer() {
        const ScrollView = api_1.API.ScrollView;
        const LinearLayout = api_1.API.LinearLayout;
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
        const LinearLayoutParams = api_1.API.LinearLayoutParams;
        const View = api_1.API.View;
        const tabRootsWrapper = LinearLayout.$new(this.context);
        tabRootsWrapper.setOrientation(LinearLayout.VERTICAL.value);
        tabRootsWrapper.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        if (!this.tabs || this.tabs.size === 0) {
            console.warn("[FloatMenu] tabs is empty, tab container will be blank.");
        }
        let firstTabId = null;
        let firstTabInfo = null;
        for (const [tabId, tabInfo] of this.tabs) {
            if (!firstTabId) {
                firstTabId = tabId;
                firstTabInfo = tabInfo;
            }
            const sv = ScrollView.$new(this.context);
            sv.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, 0, 1.0));
            try {
                sv.setBackgroundColor(0x00000000);
            }
            catch (e) { }
            try {
                sv.setFillViewport(true);
                sv.setVerticalScrollBarEnabled(false);
            }
            catch (e) { }
            const tabContainer = LinearLayout.$new(this.context);
            tabContainer.setOrientation(LinearLayout.VERTICAL.value);
            tabContainer.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
            tabContainer.setPadding((0, style_1.dp)(this.context, 10), (0, style_1.dp)(this.context, 10), (0, style_1.dp)(this.context, 10), (0, style_1.dp)(this.context, 10));
            tabContainer.setPadding(0, 0, 0, (0, style_1.dp)(this.context, 4));
            sv.addView(tabContainer);
            if (tabId === this.activeTabId) {
                sv.setVisibility(View.VISIBLE.value);
                this.currentContentContainer = tabContainer;
                this.currentScrollView = sv;
            }
            else {
                sv.setVisibility(View.GONE.value);
            }
            tabInfo.container = tabContainer;
            tabInfo.scrollView = sv;
            tabInfo.root = sv;
            tabRootsWrapper.addView(sv);
        }
        if ((!this.currentContentContainer || !this.currentScrollView) &&
            firstTabId &&
            firstTabInfo) {
            this.activeTabId = firstTabId;
            if (firstTabInfo.root)
                firstTabInfo.root.setVisibility(View.VISIBLE.value);
            this.currentContentContainer = firstTabInfo.container;
            this.currentScrollView = firstTabInfo.scrollView;
        }
        this.parentView.addView(tabRootsWrapper);
    }
}
exports.TabsView = TabsView;
