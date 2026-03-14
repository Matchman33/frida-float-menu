import { EventEmitter } from "./event-emitter";
import { Logger } from "./logger";
import { API } from "./api";
import { applyStyle, dp } from "./component/style/style";
import { DarkNeonTheme } from "./component/style/theme";
import { logicalToWindow, windowToLogical } from "./utils";
import { TabsView } from "./component/views/tabs-view";
import { HeaderView } from "./component/views/header-view";
export class FloatMenu {
    get context() {
        if (this._context === null) {
            this._context = Java.use("android.app.ActivityThread")
                .currentApplication()
                .getApplicationContext();
        }
        return this._context;
    }
    get windowManager() {
        if (this._windowManager === null) {
            const Context = API.Context;
            this._windowManager = Java.cast(this.context.getSystemService(Context.WINDOW_SERVICE.value), API.ViewManager);
        }
        return this._windowManager;
    }
    constructor(options = {}) {
        this.uiComponents = new Map();
        this.pendingComponents = [];
        this.eventEmitter = new EventEmitter();
        this.isIconMode = true;
        this._context = null;
        this._windowManager = null;
        this.options = {
            width: 1200,
            height: 1400,
            x: 0,
            y: 0,
            iconWidth: 200,
            iconHeight: 200,
            logMaxLines: 100,
            title: "Frida Float Menu",
            theme: DarkNeonTheme,
            tabs: [],
            activeTab: undefined,
            ...options,
        };
        this.logger = Logger.instance;
        Java.perform(() => {
            const resources = this.context.getResources();
            const metrics = resources.getDisplayMetrics();
            this.screenWidth = metrics.widthPixels.value;
            this.screenHeight = metrics.heightPixels.value;
            this.options.height = Math.min(this.options.height, this.screenHeight - 80);
        });
        this.logger.info("屏幕尺寸:", this.screenWidth, this.screenHeight);
        this.headerComponent = new HeaderView(this.options.theme);
        this.tabsView = new TabsView(this.context, this.options.theme, this.options.tabs, this.options.activeTab);
        this.tabsView.initializeTabs();
        this.logger.info("悬浮窗初始化完成,等待显示");
    }
    addDragListener(targetView, window, winParams) {
        const OnTouchListener = API.OnTouchListener;
        const MotionEvent = API.MotionEvent;
        targetView.setClickable(true);
        const getBounds = () => {
            const w = this.isIconMode ? this.options.iconWidth : this.options.width;
            const h = this.isIconMode
                ? this.options.iconHeight
                : this.options.height;
            return {
                left: 0,
                top: -40,
                right: this.screenWidth - w,
                bottom: this.screenHeight - h,
            };
        };
        const self = this;
        let isDragging = false;
        const DRAG_THRESHOLD = 5;
        let touchOffsetX = 0;
        let touchOffsetY = 0;
        const touchListener = Java.registerClass({
            name: "com.frida.FloatDragListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [OnTouchListener],
            methods: {
                onTouch: function (v, event) {
                    const action = event.getAction();
                    switch (action) {
                        case MotionEvent.ACTION_DOWN.value: {
                            isDragging = false;
                            const rawX = event.getRawX();
                            const rawY = event.getRawY();
                            const startWx = winParams.x.value;
                            const startWy = winParams.y.value;
                            touchOffsetX = rawX - startWx;
                            touchOffsetY = rawY - startWy;
                            self.lastTouchX = rawX;
                            self.lastTouchY = rawY;
                            return true;
                        }
                        case MotionEvent.ACTION_MOVE.value: {
                            const rawX = event.getRawX();
                            const rawY = event.getRawY();
                            const dx = rawX - self.lastTouchX;
                            const dy = rawY - self.lastTouchY;
                            if (!isDragging &&
                                (Math.abs(dx) > DRAG_THRESHOLD || Math.abs(dy) > DRAG_THRESHOLD)) {
                                isDragging = true;
                            }
                            if (isDragging) {
                                let wx = rawX - touchOffsetX;
                                let wy = rawY - touchOffsetY;
                                const p = windowToLogical(wx, wy, self.screenWidth, self.screenHeight, self.isIconMode
                                    ? self.options.iconWidth
                                    : self.options.width, self.isIconMode
                                    ? self.options.iconHeight
                                    : self.options.height);
                                let newX = p.x;
                                let newY = p.y;
                                const bounds = getBounds();
                                newX = Math.max(bounds.left, Math.min(bounds.right, newX));
                                newY = Math.max(bounds.top, Math.min(bounds.bottom, newY));
                                self.updatePosition(window, winParams, { x: newX, y: newY });
                            }
                            return true;
                        }
                        case MotionEvent.ACTION_UP.value:
                        case MotionEvent.ACTION_CANCEL.value: {
                            if (!isDragging) {
                                try {
                                    self.isIconMode = false;
                                    self.iconContainerWin.setAlpha(1);
                                    self.toggleView();
                                }
                                catch { }
                            }
                            return true;
                        }
                    }
                },
            },
        });
        targetView.setOnTouchListener(touchListener.$new());
    }
    createMenuContainerWindow() {
        const FrameLayout = API.FrameLayout;
        const LinearLayout = API.LinearLayout;
        const FrameLayoutParams = API.FrameLayoutParams;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const View = API.View;
        const LayoutParams = API.LayoutParams;
        this.menuContainerWin = FrameLayout.$new(this.context);
        const rootLp = FrameLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.MATCH_PARENT.value);
        rootLp.gravity = API.Gravity.TOP.value | API.Gravity.START.value;
        this.menuContainerWin.setLayoutParams(rootLp);
        try {
            this.menuContainerWin.setBackgroundColor(0x00000000);
        }
        catch (e) { }
        const panel = LinearLayout.$new(this.context);
        panel.setOrientation(LinearLayout.VERTICAL.value);
        panel.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.MATCH_PARENT.value));
        applyStyle(panel, "overlay", this.options.theme);
        try {
            panel.setClipToOutline(true);
        }
        catch (e) { }
        try {
            panel.setClipChildren(false);
        }
        catch (e) { }
        try {
            panel.setClipToPadding(false);
        }
        catch (e) { }
        this.menuPanelView = panel;
        this.menuContainerWin.addView(panel);
        this.menuWindowParams = LayoutParams.$new(this.options.width, this.options.height, 0, 0, 2038, LayoutParams.FLAG_NOT_FOCUSABLE.value |
            LayoutParams.FLAG_NOT_TOUCH_MODAL.value, 1);
        this.headerView = this.headerComponent.createView({
            context: this.context,
            parent: this.menuPanelView,
            logMaxLines: this.options.logMaxLines,
            title: this.options.title,
            version: "v2.4.0",
        }, {
            onMinimize: () => {
                this.isIconMode = true;
                this.toggleView();
            },
            onHide: () => {
                this.isIconMode = true;
                this.toggleView();
                this.hide();
                this.toast("菜单已隐藏,单击原来位置显示");
            },
        });
        if (this.headerView) {
            this.addDragListener(this.headerView, this.menuContainerWin, this.menuWindowParams);
        }
        this.tabsView.createTabView(this.menuPanelView);
        this.tabsView.createTabContainer();
        this.windowManager.addView(this.menuContainerWin, this.menuWindowParams);
        this.menuContainerWin.setVisibility(View.GONE.value);
    }
    updatePosition(window, winParams, newPos) {
        const { x: wx, y: wy } = logicalToWindow(newPos.x, newPos.y, this.screenWidth, this.screenHeight, this.isIconMode ? this.options.iconWidth : this.options.width, this.isIconMode ? this.options.iconHeight : this.options.height);
        winParams.x.value = wx | 0;
        winParams.y.value = wy | 0;
        Java.scheduleOnMainThread(() => {
            this.windowManager.updateViewLayout(window, winParams);
        });
    }
    createIconWindow() {
        const ImageView = API.ImageView;
        const ImageView$ScaleType = API.ImageViewScaleType;
        const FrameLayoutParams = API.FrameLayoutParams;
        const Gravity = API.Gravity;
        const LayoutParams = API.LayoutParams;
        const BitmapFactory = API.BitmapFactory;
        const Base64 = API.Base64;
        const FrameLayout = API.FrameLayout;
        this.iconView = ImageView.$new(this.context);
        if (this.options.iconBase64) {
            const decoded = Base64.decode(this.options.iconBase64, Base64.DEFAULT.value);
            const bitmap = BitmapFactory.decodeByteArray(decoded, 0, decoded.length);
            this.iconView.setImageBitmap(bitmap);
        }
        else {
            this.iconView.setBackgroundColor(0xff4285f4 | 0);
            try {
                this.iconView.setClipToOutline(true);
            }
            catch { }
        }
        this.iconView.setScaleType(ImageView$ScaleType.FIT_CENTER.value);
        const { x, y } = logicalToWindow(this.options.x, this.options.y, this.screenWidth, this.screenHeight, this.options.iconWidth, this.options.iconHeight);
        this.iconWindowParams = LayoutParams.$new(this.options.iconWidth, this.options.iconHeight, x, y, 2038, LayoutParams.FLAG_NOT_FOCUSABLE.value |
            LayoutParams.FLAG_NOT_TOUCH_MODAL.value, 1);
        this.iconContainerWin = FrameLayout.$new(this.context);
        this.iconContainerWin.setLayoutParams(FrameLayoutParams.$new(this.options.iconWidth, this.options.iconHeight, Gravity.CENTER.value));
        this.iconContainerWin.addView(this.iconView);
        this.windowManager.addView(this.iconContainerWin, this.iconWindowParams);
        this.addDragListener(this.iconContainerWin, this.iconContainerWin, this.iconWindowParams);
    }
    toggleView() {
        Java.scheduleOnMainThread(() => {
            const View = API.View;
            if (this.isIconMode) {
                this.menuContainerWin.setVisibility(View.GONE.value);
                this.iconContainerWin.setVisibility(View.VISIBLE.value);
            }
            else {
                this.menuContainerWin.setVisibility(View.VISIBLE.value);
                this.iconContainerWin.setVisibility(View.GONE.value);
            }
        });
    }
    show() {
        Java.scheduleOnMainThread(() => {
            const Settings = Java.use("android.provider.Settings");
            if (!Settings.canDrawOverlays(this.context)) {
                this.toast("进程没有悬浮窗权限!");
                Logger.instance.error("Draw overlays permission not granted");
                return;
            }
            try {
                this.createIconWindow();
                this.createMenuContainerWindow();
                this.processPendingComponents(this.context);
            }
            catch (error) {
                Logger.instance.error("Failed to show floating window: ", error);
            }
        });
    }
    bindComponentEvents(component) {
        const id = component.getId();
        component.on("valueChanged", (value) => {
            this.eventEmitter.emit("component:" + id + ":valueChanged", value);
        });
        component.on("action", (data) => {
            this.eventEmitter.emit("component:" + id + ":action", data);
        });
        component.on("click", (data) => {
            this.eventEmitter.emit("component:" + id + ":click", data);
        });
    }
    processPendingComponents(context) {
        if (this.pendingComponents.length === 0)
            return;
        this.logger.debug(`Processing ${this.pendingComponents.length} pending components`);
        for (const { id, component, tabId } of this.pendingComponents) {
            try {
                const tabInfo = this.tabsView.tabs.get(tabId);
                if (!tabInfo) {
                    this.logger.error(`Cannot add pending component ${id} - tab ${tabId} not found`);
                    continue;
                }
                const view = this.prepareComponentView(context, component);
                if (tabInfo.container) {
                    tabInfo.container.addView(view);
                }
                else {
                    this.tabsView.currentContentContainer.addView(view);
                }
                tabInfo.components.add(id);
                this.bindComponentEvents(component);
            }
            catch (error) {
                Logger.instance.error(`Failed to add pending component ${id}: ` + error);
            }
        }
        this.pendingComponents = [];
    }
    prepareComponentView(context, component) {
        const LinearLayoutParams = API.LinearLayoutParams;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const gapNormal = dp(context, 10);
        component.init(context);
        const view = component.getView();
        const lp = LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value);
        lp.setMargins(0, 0, 0, gapNormal);
        view.setLayoutParams(lp);
        return view;
    }
    hide() {
        Java.scheduleOnMainThread(() => {
            try {
                this.iconContainerWin.setAlpha(0);
                this.windowManager.updateViewLayout(this.iconContainerWin, this.iconWindowParams);
            }
            catch (error) {
                Logger.instance.error("Failed to hide floating window: " + error);
            }
        });
    }
    toast(msg, duration = 0) {
        Java.scheduleOnMainThread(() => {
            var toast = Java.use("android.widget.Toast");
            toast
                .makeText(this.context, Java.use("java.lang.String").$new(msg), duration)
                .show();
        });
    }
    addComponent(component, tabId) {
        const id = component.getId();
        const targetTabId = tabId || this.tabsView.activeTabId;
        const tabInfo = this.tabsView.tabs.get(targetTabId);
        if (!tabInfo) {
            Logger.instance.error(`Cannot add component ${id} - tab ${targetTabId} not found`);
            return;
        }
        this.uiComponents.set(id, component);
        component.setMenu(this);
        tabInfo.components.add(id);
        if (!this.menuPanelView) {
            this.pendingComponents.push({ id, component, tabId: targetTabId });
            Logger.instance.debug(`Component ${id} queued for tab ${targetTabId} (window not shown)`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const context = this.menuPanelView.getContext();
            const view = this.prepareComponentView(context, component);
            if (tabInfo.container) {
                tabInfo.container.addView(view);
            }
            else {
                Logger.instance.warn(`Tab container for ${targetTabId} not found, using contentContainer`);
                this.tabsView.currentContentContainer.addView(view);
            }
            this.bindComponentEvents(component);
        });
    }
    removeComponent(id) {
        const component = this.uiComponents.get(id);
        if (!component)
            return;
        let targetTabId = null;
        for (const [tabId, tabInfo] of this.tabsView.tabs) {
            if (tabInfo.components.has(id)) {
                targetTabId = tabId;
                break;
            }
        }
        this.pendingComponents = this.pendingComponents.filter((p) => p.id !== id);
        Java.scheduleOnMainThread(() => {
            const view = component.getView();
            if (targetTabId) {
                const tabInfo = this.tabsView.tabs.get(targetTabId);
                if (tabInfo && tabInfo.container) {
                    try {
                        tabInfo.container.removeView(view);
                    }
                    catch (e) {
                        if (this.tabsView.currentContentContainer) {
                            try {
                                this.tabsView.currentContentContainer.removeView(view);
                            }
                            catch (e2) {
                            }
                        }
                    }
                }
                else if (this.tabsView.currentContentContainer) {
                    try {
                        this.tabsView.currentContentContainer.removeView(view);
                    }
                    catch (e) {
                    }
                }
            }
            else {
                if (this.tabsView.currentContentContainer) {
                    try {
                        this.tabsView.currentContentContainer.removeView(view);
                    }
                    catch (e) {
                        this.menuContainerWin.removeView(view);
                    }
                }
                else if (this.menuContainerWin) {
                    this.menuContainerWin.removeView(view);
                }
                else
                    Logger.instance.error("error");
            }
        });
        if (targetTabId) {
            const tabInfo = this.tabsView.tabs.get(targetTabId);
            if (tabInfo) {
                tabInfo.components.delete(id);
            }
        }
        this.uiComponents.delete(id);
        Logger.instance.debug(`Component ${id} removed${targetTabId ? ` from tab ${targetTabId}` : ""}`);
    }
    getComponent(id) {
        return this.uiComponents.get(id);
    }
    setComponentValue(id, value) {
        const component = this.uiComponents.get(id);
        if (component) {
            component.setValue(value);
        }
    }
    on(event, callback) {
        this.eventEmitter.on(event, callback);
    }
    off(event, callback) {
        this.eventEmitter.off(event, callback);
    }
}
