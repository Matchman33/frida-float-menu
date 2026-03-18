import Java from "frida-java-bridge";
import { API } from "../../api.js";
import { EventEmitter } from "../../event-emitter.js";
import { Logger } from "../../logger.js";
import { dp } from "../style/style.js";
export class TabsView {
    constructor(context, theme, initTabs, activeTabId) {
        this.tabs = new Map();
        this.logger = Logger.instance;
        this.eventEmitter = new EventEmitter();
        this.tabItemMap = new Map();
        this.context = context;
        this.theme = theme;
        this.initTabs = initTabs;
        this.activeTabId = activeTabId;
    }
    createTabView(parentView) {
        this.parentView = parentView;
        if (this.tabs.size === 1 && this.tabs.has("default")) {
            return;
        }
        this.tabItemMap.clear();
        try {
            const LinearLayout = API.LinearLayout;
            const LinearLayoutParams = API.LinearLayoutParams;
            const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
            const TextView = API.TextView;
            const OnClickListener = API.OnClickListener;
            const JString = API.JString;
            const HorizontalScrollView = API.HorizontalScrollView;
            const GradientDrawable = API.GradientDrawable;
            const Gravity = API.Gravity;
            const self = this;
            const outerScroll = HorizontalScrollView.$new(this.context);
            outerScroll.setHorizontalScrollBarEnabled(false);
            outerScroll.setFillViewport(false);
            outerScroll.setPadding(dp(this.context, 12), dp(this.context, 6), dp(this.context, 12), dp(this.context, 6));
            const scrollLp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
            scrollLp.setMargins(0, 0, 0, 0);
            outerScroll.setLayoutParams(scrollLp);
            try {
                outerScroll.setClipToPadding(false);
            }
            catch { }
            try {
                outerScroll.setClipChildren(false);
            }
            catch { }
            const tabContainer = LinearLayout.$new(this.context);
            tabContainer.setOrientation(0);
            tabContainer.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.WRAP_CONTENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
            tabContainer.setPadding(0, 0, 0, 0);
            this.tabContainer = tabContainer;
            outerScroll.addView(tabContainer);
            const tabBarRoot = LinearLayout.$new(this.context);
            tabBarRoot.setOrientation(1);
            tabBarRoot.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
            this.tabScrollView = outerScroll;
            const indicator = API.View.$new(this.context);
            const indicatorLp = LinearLayoutParams.$new(dp(this.context, 0), dp(this.context, 2));
            indicatorLp.setMargins(dp(this.context, 12), dp(this.context, 2), dp(this.context, 12), dp(this.context, 0));
            indicator.setLayoutParams(indicatorLp);
            indicator.setBackgroundColor(0xffffffff | 0);
            this.tabIndicatorView = indicator;
            tabBarRoot.addView(outerScroll);
            tabBarRoot.addView(indicator);
            this.tabView = tabBarRoot;
            for (const [tabId, tabInfo] of this.tabs) {
                const tabItem = LinearLayout.$new(this.context);
                tabItem.setOrientation(1);
                tabItem.setGravity(Gravity.CENTER.value);
                try {
                    tabItem.setBackground(null);
                }
                catch { }
                try {
                    tabItem.setBackgroundColor(0x00000000);
                }
                catch { }
                tabItem.setPadding(dp(this.context, 12), dp(this.context, 6), dp(this.context, 12), dp(this.context, 0));
                this.tabItemMap.set(tabId, tabItem);
                const itemLp = LinearLayoutParams.$new(ViewGroupLayoutParams.WRAP_CONTENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
                itemLp.setMargins(0, 0, 0, 0);
                tabItem.setLayoutParams(itemLp);
                const label = TextView.$new(this.context);
                label.setText(JString.$new(tabInfo.label));
                label.setSingleLine(true);
                label.setAllCaps(false);
                label.setTextSize(2, this.theme.textSp.body);
                label.setGravity(Gravity.CENTER.value);
                try {
                    label.setBackground(null);
                }
                catch {
                    try {
                        label.setBackgroundColor(0x00000000);
                    }
                    catch { }
                }
                const underline = API.View.$new(this.context);
                const ulLp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, dp(this.context, 2));
                ulLp.setMargins(0, dp(this.context, 6), 0, 0);
                underline.setLayoutParams(ulLp);
                underline.setBackgroundColor(this.theme.colors.accent);
                underline.setVisibility(API.View.GONE.value);
                tabItem.addView(label);
                tabItem.addView(underline);
                this.updateTabStyle(tabItem, tabId === this.activeTabId);
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
                tabItem.setOnClickListener(tabClickListener.$new());
                tabContainer.addView(tabItem);
            }
            parentView.addView(this.tabView);
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
        Java.scheduleOnMainThread(() => {
            try {
                const View = API.View;
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
                this.refreshTabsUI();
                this.eventEmitter.emit("tabChanged", tabId, oldTabId);
            }
            catch (error) {
                Logger.instance.error(`Failed to switch to tab ${tabId}:`, error);
            }
        });
    }
    updateTabStyle(tabItem, isActive) {
        try {
            const View = API.View;
            const TextView = API.TextView;
            const label = Java.cast(tabItem.getChildAt(0), TextView);
            const underline = tabItem.getChildAt(1);
            if (isActive) {
                label.setTextColor(this.theme.colors.text);
                try {
                    label.setTypeface(null, 1);
                }
                catch { }
                underline.setVisibility(View.VISIBLE.value);
            }
            else {
                label.setTextColor(this.theme.colors.subText);
                try {
                    label.setTypeface(null, 0);
                }
                catch { }
                underline.setVisibility(View.GONE.value);
            }
        }
        catch (e) {
            Logger.instance.error(e);
        }
    }
    updateTabIndicator(activeTabId) {
        try {
            if (!this.tabContainer || !this.tabIndicatorView || !this.tabScrollView)
                return;
            const tabIds = Array.from(this.tabs.keys());
            const idx = tabIds.indexOf(activeTabId);
            if (idx < 0)
                return;
            const child = this.tabContainer.getChildAt(idx);
            if (!child)
                return;
            const indicator = this.tabIndicatorView;
            const scroll = this.tabScrollView;
            scroll.post(Java.registerClass({
                name: "TabIndicatorPost_" +
                    Date.now() +
                    Math.random().toString(36).slice(2),
                implements: [Java.use("java.lang.Runnable")],
                methods: {
                    run: () => {
                        try {
                            const width = child.getWidth();
                            const leftInContainer = child.getLeft();
                            const scrollX = scroll.getScrollX();
                            const padL = scroll.getPaddingLeft();
                            const lp = indicator.getLayoutParams();
                            lp.width = width;
                            lp.leftMargin = padL + leftInContainer - scrollX;
                            indicator.setLayoutParams(lp);
                        }
                        catch { }
                    },
                },
            }).$new());
        }
        catch (e) { }
    }
    refreshTabsUI() {
        try {
            if (!this.tabItemMap)
                return;
            for (const [tabId, tabItem] of this.tabItemMap) {
                this.updateTabStyle(tabItem, tabId === this.activeTabId);
            }
        }
        catch (e) {
            Logger.instance.error(e);
        }
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
        const ScrollView = API.ScrollView;
        const LinearLayout = API.LinearLayout;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const LinearLayoutParams = API.LinearLayoutParams;
        const View = API.View;
        const tabRootsWrapper = LinearLayout.$new(this.context);
        tabRootsWrapper.setOrientation(LinearLayout.VERTICAL.value);
        tabRootsWrapper.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        if (!this.tabs || this.tabs.size === 0) {
            Logger.instance.warn("[FloatMenu] tabs is empty, tab container will be blank.");
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
