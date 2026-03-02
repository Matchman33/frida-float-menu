import { EventEmitter } from "./event-emitter";
import { UIComponent } from "./component/ui-components";
import { Logger, LogLevel } from "./logger";
import { API } from "./api";
import { dp, applyStyle } from "./component/style/style";
import { DarkNeonTheme } from "./component/style/theme";

export interface TabDefinition {
  id: string;
  label: string;
}

export interface FloatMenuOptions {
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  iconWidth?: number;
  iconHeight?: number;
  iconBase64?: string; // base64 encoded icon for floating window
  showLogs?: boolean; // whether to show log panel
  logMaxLines?: number;
  title?: string; // Main title text (default: "Frida Float Menu")
  showFooter?: boolean; // Whether to show footer (default: true)
  tabs?: TabDefinition[]; // Tab definitions (optional)
  activeTab?: string; // Initially active tab ID (default: first tab or "default")
  showTabs?: boolean; // Whether to show tab bar (default: true if tabs are defined)
}

export class FloatMenu {
  private options: FloatMenuOptions;
  private menuContainerView: any; // Outer layout containing header, scrollable content and footer
  private contentContainer: any; // Scrollable content area (LinearLayout inside ScrollView)
  private scrollView: any; // ScrollView wrapping contentContainer
  private headerView: any; // Header area with title and subtitle
  private footerView: any; // Footer area with buttons
  private iconView: any; // ImageView for icon
  private uiComponents: Map<string, UIComponent> = new Map();
  private pendingComponents: Array<{
    id: string;
    component: UIComponent;
    tabId: string;
  }> = [];
  private logView: any; // TextView or ListView for logs
  private eventEmitter: EventEmitter = new EventEmitter();
  private logger: Logger;
  private isIconMode: boolean = true; // Whether currently showing icon or menu

  // Tab management
  private tabs: Map<
    string,
    {
      label: string;
      container: any; // ✅ 内容 LinearLayout（你 addView 用它）
      root?: any; // ✅ 这个 tab 的根视图（建议就是 ScrollView）
      scrollView?: any; // ✅ 这个 tab 自己的 ScrollView
      components: Set<string>;
    }
  > = new Map();
  private tabView: any; // Tab bar view (LinearLayout with buttons)
  private activeTabId: string = "default"; // Currently active tab ID

  private _context: any = null;
  private lastTouchX: any;
  private lastTouchY: any;
  private initialWindowX: any;
  private initialWindowY: any;
  private screenWidth: any;
  private screenHeight: any;
  private menuWindowParams: any;
  private iconWindowParams: any;
  private iconContainerView: any;
  private tabContainer: any;
  public get context(): any {
    if (this._context === null) {
      this._context = Java.use("android.app.ActivityThread")
        .currentApplication()
        .getApplicationContext();
    }
    return this._context;
  }
  private _windowManager: any = null;

  public get windowManager(): any {
    if (this._windowManager === null) {
      const Context = API.Context;
      this._windowManager = Java.cast(
        this.context.getSystemService(Context.WINDOW_SERVICE.value),
        API.ViewManager,
      );
    }
    return this._windowManager;
  }

  constructor(options: FloatMenuOptions = {}) {
    this.options = {
      width: 1000,
      height: 900,
      x: 0,
      y: 0,
      iconWidth: 200,
      iconHeight: 200,
      showLogs: false,
      logMaxLines: 100,
      title: "Frida Float Menu",
      showFooter: true,
      tabs: undefined,
      activeTab: undefined,
      showTabs: undefined, // Will be determined based on tabs array
      ...options,
    };
    Java.perform(() => {
      const resources = this.context.getResources();
      const metrics = resources.getDisplayMetrics();

      this.screenWidth = metrics.widthPixels.value;
      this.screenHeight = metrics.heightPixels.value;
      this.options.height = Math.min(
        this.options.height!,
        this.screenHeight - 80,
      );
    });
    console.log("屏幕尺寸:", this.screenWidth, this.screenHeight);

    this.logger = new Logger(this.options.showLogs ? "debug" : "none");
    if (this.options.showLogs) {
      this.logger.on("log", (level: LogLevel, message: string) => {
        this.addLogToView(level, message);
      });
    }

    // Initialize tabs
    this.initializeTabs();

    console.info("FloatMenu initialized");
  }

  /**
   * Initialize tabs from options
   */
  private initializeTabs(): void {
    // Clear existing tabs
    this.tabs.clear();

    // Determine if we should show tabs
    if (this.options.tabs && this.options.tabs.length > 0) {
      // If showTabs is not explicitly set, default to true when tabs are defined
      if (this.options.showTabs === undefined) {
        this.options.showTabs = true;
      }

      // Create tab entries
      for (const tabDef of this.options.tabs) {
        this.tabs.set(tabDef.id, {
          label: tabDef.label,
          container: null, // Will be created in show()
          components: new Set<string>(),
        });
      }

      // Set active tab
      if (this.options.activeTab && this.tabs.has(this.options.activeTab)) {
        this.activeTabId = this.options.activeTab;
      } else if (this.options.tabs.length > 0) {
        this.activeTabId = this.options.tabs[0].id;
      }
    } else {
      // No tabs defined, create default tab
      this.tabs.set("default", {
        label: "Default",
        container: null,
        components: new Set<string>(),
      });
      this.activeTabId = "default";
      this.options.showTabs = false; // Don't show tab bar for single default tab
    }
  }

  /**
   * 逻辑坐标转换为真实坐标，以左上角为原点转换为屏幕中心为原点
   * @param lx
   * @param ly
   * @returns
   */
  private logicalToWindow(lx: number, ly: number) {
    const sw = this.screenWidth;
    const sh = this.screenHeight;
    const iw = this.options.iconWidth!;
    const ih = this.options.iconHeight!;
    return {
      x: Math.round(lx - (sw - iw) / 2),
      y: Math.round(ly - (sh - ih) / 2),
    };
  }

  /**
   * 真实坐标转换为逻辑坐标，以左上角为原点转换为屏幕中心为原点
   * @param wx
   * @param wy
   * @returns
   */
  private windowToLogical(wx: number, wy: number) {
    const sw = this.screenWidth;
    const sh = this.screenHeight;
    const iw = this.options.iconWidth!;
    const ih = this.options.iconHeight!;
    return {
      x: Math.round(wx + (sw - iw) / 2),
      y: Math.round(wy + (sh - ih) / 2),
    };
  }

  private addDragListener(targetView: any, window: any, winParams: any) {
    const OnTouchListener = API.OnTouchListener;
    const MotionEvent = API.MotionEvent;
    targetView.setClickable(true);
    // 拖动
    const bounds = {
      left: 0,
      top: 0,
      right: this.screenWidth - this.options.iconWidth!,
      bottom: this.screenHeight - this.options.iconHeight!,
    };
    let isDragging = false;
    const self = this;

    const DRAG_THRESHOLD = 5; // 阈值，小于 5px 不算拖动

    const touchListener = Java.registerClass({
      name:
        "com.frida.FloatDragListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnTouchListener],
      methods: {
        onTouch: function (v: any, event: any) {
          const action = event.getAction();

          switch (action) {
            case MotionEvent.ACTION_DOWN.value:
              isDragging = false;

              self.lastTouchX = event.getRawX();
              self.lastTouchY = event.getRawY();

              self.initialWindowX = winParams.x.value;
              self.initialWindowY = winParams.y.value;

              return false;
            case MotionEvent.ACTION_MOVE.value: {
              const dx = event.getRawX() - self.lastTouchX;
              const dy = event.getRawY() - self.lastTouchY;

              if (
                Math.abs(dx) > DRAG_THRESHOLD ||
                Math.abs(dy) > DRAG_THRESHOLD
              ) {
                isDragging = true;

                let newX = self.initialWindowX + dx;
                let newY = self.initialWindowY + dy;

                // window → logical
                const { x, y } = self.windowToLogical(newX, newY);
                newX = x;
                newY = y;

                // 边界限制（logical 坐标）
                newX = Math.max(bounds.left, Math.min(bounds.right, newX));
                newY = Math.max(bounds.top, Math.min(bounds.bottom, newY));

                // 同步更新icon + menu 坐标
                self.updatePosition(window, winParams, { x: newX, y: newY });
              }

              return isDragging;
            }

            case MotionEvent.ACTION_UP.value:
              return isDragging; // 拖动时消耗事件，避免触发点击
          }

          return false;
        },
      },
    });
    targetView.setOnTouchListener(touchListener.$new());
  }

  private createMenuContainerWindow() {
    const LinearLayout = API.LinearLayout;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const View = API.View;

    // --------------------
    // 创建 menu 容器
    // --------------------
    this.menuContainerView = LinearLayout.$new(this.context);

    this.menuContainerView.setOrientation(1); // VERTICAL
    const layoutParams = ViewGroupLayoutParams.$new(
      ViewGroupLayoutParams.MATCH_PARENT.value,
      ViewGroupLayoutParams.MATCH_PARENT.value,
    );
    this.menuContainerView.setLayoutParams(layoutParams);
    const LayoutParams = API.LayoutParams;
    this.menuWindowParams = LayoutParams.$new(
      this.options.width,
      this.options.height,
      0,
      0,
      2038, // TYPE_APPLICATION_OVERLAY
      // 必须添加FLAG_NOT_FOCUSABLE防止游戏卡死
      LayoutParams.FLAG_NOT_FOCUSABLE.value |
        LayoutParams.FLAG_NOT_TOUCH_MODAL.value,
      1, // PixelFormat.TRANSLUCENT
    );

    this.createHeaderView(this.context);
    this.menuContainerView.addView(this.headerView);

    // tab bar
    if (this.options.showTabs) {
      this.createTabView(this.context);

      this.menuContainerView.addView(this.tabView);
    }

    this.createTabContainer(this.context);

    // this.menuContainerView.addView(this.scrollView);

    // footer
    // if (this.options.showFooter) {
    //   this.createFooterView(this.context);
    //   this.menuContainerView.addView(this.footerView);
    // }

    this.windowManager.addView(this.menuContainerView, this.menuWindowParams);
    this.menuContainerView.setVisibility(View.GONE.value);
  }
  private updatePosition(
    window: any,
    winParams: any,
    newPos: { x: number; y: number },
  ): void {
    // icon
    const { x: wx, y: wy } = this.logicalToWindow(newPos.x, newPos.y);
    winParams.x.value = wx | 0;
    winParams.y.value = wy | 0;

    Java.scheduleOnMainThread(() => {
      this.windowManager.updateViewLayout(window, winParams);
    });

    // 刷新
  }
  private createIconWindow(): void {
    try {
      const ImageView = API.ImageView;
      const ImageView$ScaleType = API.ImageViewScaleType;
      const FrameLayoutParams = API.FrameLayoutParams;
      const OnClickListener = API.OnClickListener;
      const Gravity = API.Gravity;
      const LayoutParams = API.LayoutParams;
      const BitmapFactory = API.BitmapFactory;
      const Base64 = API.Base64;
      const FrameLayout = API.FrameLayout;

      this.iconView = ImageView.$new(this.context);

      // icon 图片或默认圆
      if (this.options.iconBase64) {
        const decoded = Base64.decode(
          this.options.iconBase64,
          Base64.DEFAULT.value,
        );
        const bitmap = BitmapFactory.decodeByteArray(
          decoded,
          0,
          decoded.length,
        );
        this.iconView.setImageBitmap(bitmap);
      } else {
        this.iconView.setBackgroundColor(0xff4285f4 | 0);
        try {
          this.iconView.setClipToOutline(true);
        } catch {}
      }

      this.iconView.setScaleType(ImageView$ScaleType.FIT_CENTER.value);

      const { x, y } = this.logicalToWindow(this.options.x!, this.options.y!);
      // icon window
      this.iconWindowParams = LayoutParams.$new(
        this.options.iconWidth,
        this.options.iconHeight,
        x,
        y,
        2038,
        LayoutParams.FLAG_NOT_FOCUSABLE.value |
          LayoutParams.FLAG_NOT_TOUCH_MODAL.value,
        1,
      );

      this.iconContainerView = FrameLayout.$new(this.context);
      this.iconContainerView.setLayoutParams(
        FrameLayoutParams.$new(
          this.options.iconWidth,
          this.options.iconHeight,
          Gravity.CENTER.value,
        ),
      );
      this.iconContainerView.addView(this.iconView);

      // 添加到 window manager
      this.windowManager.addView(this.iconContainerView, this.iconWindowParams);

      const self = this;
      // 点击切换 menu

      const clickListener = Java.registerClass({
        name: "com.frida.IconClickListener" + Date.now(),
        implements: [OnClickListener],
        methods: {
          onClick: function () {
            self.isIconMode = false;

            // 再次被点击以后设置为不透明
            self.iconContainerView.setAlpha(1);

            self.toggleView();
          },
        },
      });
      this.iconContainerView.setOnClickListener(clickListener.$new());
      this.addDragListener(
        this.iconContainerView,
        this.iconContainerView,
        this.iconWindowParams,
      );
    } catch (error) {
      console.trace("Failed to create icon view: " + error);
    }
  }

  /**
   * Toggle between icon and menu view
   */
  public toggleView(): void {
    Java.scheduleOnMainThread(() => {
      const View = API.View;
      if (this.isIconMode) {
        this.menuContainerView.setVisibility(View.GONE.value);
        this.iconContainerView.setVisibility(View.VISIBLE.value);
      } else {
        this.menuContainerView.setVisibility(View.VISIBLE.value);
        this.iconContainerView.setVisibility(View.GONE.value);
      }
    });
  }

  /**
   * Create and show the floating window
   */
  public show(): void {
    Java.scheduleOnMainThread(() => {
      try {
        // Create icon view
        this.createIconWindow();
        this.createMenuContainerWindow();

        // Add any pending components that were added before window was shown
        this.processPendingComponents(this.context);
      } catch (error) {
        console.trace("Failed to show floating window: " + error);
      }
    });
  }

  /**
   * Process components that were added before window was shown
   */
  private processPendingComponents(context: any): void {
    if (this.pendingComponents.length === 0) return;

    console.debug(
      `Processing ${this.pendingComponents.length} pending components`,
    );
    for (const { id, component, tabId } of this.pendingComponents) {
      try {
        const tabInfo = this.tabs.get(tabId);
        if (!tabInfo) {
          console.error(
            `Cannot add pending component ${id} - tab ${tabId} not found`,
          );
          continue;
        }

        component.init(context);

        const view = component.getView();
        // // Add to the appropriate tab container
        if (tabInfo.container) {
          tabInfo.container.addView(view);
        } else {
          // Fallback to contentContainer (should not happen if tab container was created)

          this.contentContainer.addView(view);
        }

        // Record component ID in tab's component set
        tabInfo.components.add(id);

        // Bind events (same as in addComponent)
        component.on("valueChanged", (value: any) => {
          this.eventEmitter.emit("component:" + id + ":valueChanged", value);
        });
        component.on("action", (data: any) => {
          this.eventEmitter.emit("component:" + id + ":action", data);
        });
        component.on("click", (data: any) => {
          this.eventEmitter.emit("component:" + id + ":click", data);
        });
      } catch (error) {
        console.trace(`Failed to add pending component ${id}: ` + error);
      }
    }
    // Clear pending components
    this.pendingComponents = [];
  }

  /**
   * Hide and destroy the floating window
   */
  public hide(): void {
    Java.scheduleOnMainThread(() => {
      try {
        this.iconContainerView.setAlpha(0); // 完全透明
        this.windowManager.updateViewLayout(
          this.iconContainerView,
          this.iconWindowParams,
        );
      } catch (error) {
        console.error("Failed to hide floating window: " + error);
      }
    });
  }

  public toast(msg: string, duration: 0 | 1 = 0): void {
    Java.scheduleOnMainThread(() => {
      var toast = Java.use("android.widget.Toast");
      toast
        .makeText(
          this.context,
          Java.use("java.lang.String").$new(msg),
          duration,
        )
        .show();
    });
  }

  /**
   * Add a UI component to the floating window
   * @param id Unique identifier for the component
   * @param component UI component instance
   */
  public addComponent(component: UIComponent, tabId?: string): void {
    const id = component.getId();
    // Determine which tab this component belongs to
    const targetTabId = tabId || this.activeTabId;
    const tabInfo = this.tabs.get(targetTabId);
    if (!tabInfo) {
      console.error(
        `Cannot add component ${id} - tab ${targetTabId} not found`,
      );
      return;
    }

    // Store component with tab information
    this.uiComponents.set(id, component);

    // Record component ID in tab's component set
    tabInfo.components.add(id);

    if (!this.menuContainerView) {
      // Window not shown yet, queue component with tab info
      this.pendingComponents.push({ id, component, tabId: targetTabId });
      console.debug(
        `Component ${id} queued for tab ${targetTabId} (window not shown)`,
      );
      return;
    }

    // // Window is shown, add component immediately
    Java.scheduleOnMainThread(() => {
      const context = this.menuContainerView.getContext();
      component.init(context);
      const view = component.getView();

      // Add to the appropriate tab container
      if (tabInfo.container) {
        tabInfo.container.addView(view);
      } else {
        // Fallback to contentContainer (should not happen if tab container was created)
        console.warn(
          `Tab container for ${targetTabId} not found, using contentContainer`,
        );
        this.contentContainer.addView(view);
      }

      // Bind events
      component.on("valueChanged", (value: any) => {
        this.eventEmitter.emit("component:" + id + ":valueChanged", value);
      });
      component.on("action", (data: any) => {
        this.eventEmitter.emit("component:" + id + ":action", data);
      });
      component.on("click", (data: any) => {
        this.eventEmitter.emit("component:" + id + ":click", data);
      });
    });
    // console.debug(`Component ${id} added to tab ${targetTabId}`);
  }

  /**
   * Remove a UI component
   */
  public removeComponent(id: string): void {
    const component = this.uiComponents.get(id);
    if (!component) return;

    // Find which tab this component belongs to
    let targetTabId: string | null = null;
    for (const [tabId, tabInfo] of this.tabs) {
      if (tabInfo.components.has(id)) {
        targetTabId = tabId;
        break;
      }
    }

    // Remove from pending components if window not shown yet
    this.pendingComponents = this.pendingComponents.filter((p) => p.id !== id);

    Java.scheduleOnMainThread(() => {
      const view = component.getView();

      if (targetTabId) {
        // Remove from the specific tab container
        const tabInfo = this.tabs.get(targetTabId);
        if (tabInfo && tabInfo.container) {
          try {
            tabInfo.container.removeView(view);
          } catch (e) {
            // Fallback to contentContainer
            if (this.contentContainer) {
              try {
                this.contentContainer.removeView(view);
              } catch (e2) {
                // Continue to other fallbacks
              }
            }
          }
        } else if (this.contentContainer) {
          // Tab container not found, try contentContainer
          try {
            this.contentContainer.removeView(view);
          } catch (e) {
            // Continue to other fallbacks
          }
        }
      } else {
        // Component not associated with any tab (should not happen)
        // Use original fallback logic
        if (this.contentContainer) {
          try {
            this.contentContainer.removeView(view);
          } catch (e) {
            this.menuContainerView.removeView(view);
          }
        } else if (this.menuContainerView) {
          this.menuContainerView.removeView(view);
        } else console.error("error");
      }
    });

    // Remove component from tab's component set
    if (targetTabId) {
      const tabInfo = this.tabs.get(targetTabId);
      if (tabInfo) {
        tabInfo.components.delete(id);
      }
    }

    this.uiComponents.delete(id);
    console.debug(
      `Component ${id} removed${targetTabId ? ` from tab ${targetTabId}` : ""}`,
    );
  }

  /**
   * Get a component by id
   */
  public getComponent<T extends UIComponent>(id: string): T | undefined {
    return this.uiComponents.get(id) as T;
  }

  /**
   * Update component value from JS
   */
  public setComponentValue(id: string, value: any): void {
    const component = this.uiComponents.get(id);
    if (component) {
      component.setValue(value);
    }
  }

  /**
   * Register event listener for component
   */
  public on(event: string, callback: (...args: any[]) => void): void {
    this.eventEmitter.on(event, callback);
  }

  /**
   * Unregister event listener
   */
  public off(event: string, callback: (...args: any[]) => void): void {
    this.eventEmitter.off(event, callback);
  }

  private refreshTabsUI(): void {
    try {
      if (!this.tabContainer) return;

      const GradientDrawable = API.GradientDrawable;
      const count = this.tabContainer.getChildCount();

      // tabs 的遍历顺序和 child 顺序一致
      const tabIds = Array.from(this.tabs.keys());

      for (let i = 0; i < count; i++) {
        const tv = this.tabContainer.getChildAt(i);
        const tabId = tabIds[i];
        const active = tabId === this.activeTabId;

        const d = GradientDrawable.$new();
        d.setCornerRadius(dp(this.context, 12));
        if (active) {
          d.setColor(DarkNeonTheme.colors.accent);
          tv.setTextColor(0xffffffff | 0);
          try {
            tv.setTypeface(null, 1);
          } catch (e) {}
        } else {
          d.setColor(0x00000000);
          d.setStroke(dp(this.context, 1), DarkNeonTheme.colors.divider);
          tv.setTextColor(DarkNeonTheme.colors.subText);
          try {
            tv.setTypeface(null, 0);
          } catch (e) {}
        }
        tv.setBackgroundDrawable(d);
      }
    } catch (e) {}
  }
  private updateTabStyle(button: any, isActive: boolean) {
    const GradientDrawable = API.GradientDrawable;

    // dp helper（如果当前文件里没有 dp(context, x)，用你已有的那个）
    const ctx = button.getContext();

    const radius = dp(ctx, 12); // 胶囊圆角
    const strokeW = dp(ctx, 1);
    const padH = dp(ctx, 12);
    const padV = dp(ctx, 8);

    // 基础字体/内边距（避免每处都散落 setTextSize）
    try {
      button.setAllCaps(false);
    } catch (e) {}
    button.setSingleLine(true);
    button.setTextSize(2, DarkNeonTheme.textSp.body);
    button.setPadding(padH, padV, padH, padV);

    // 背景
    const drawable = GradientDrawable.$new();
    drawable.setCornerRadius(radius);

    if (isActive) {
      // ✅ 激活：accent 实心 + 白字
      drawable.setColor(DarkNeonTheme.colors.accent);
      button.setTextColor(0xffffffff | 0);
      try {
        button.setTypeface(null, 1); // bold
      } catch (e) {}
    } else {
      // ✅ 未激活：透明底 + divider 描边 + 次级文字色
      drawable.setColor(0x00000000);
      drawable.setStroke(strokeW, DarkNeonTheme.colors.divider);
      button.setTextColor(DarkNeonTheme.colors.subText);
      try {
        button.setTypeface(null, 0);
      } catch (e) {}
    }

    button.setBackgroundDrawable(drawable);
  }
  private createTabContainer(context: any): void {
    const ScrollView = API.ScrollView;
    const LinearLayout = API.LinearLayout;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const LinearLayoutParams = API.LinearLayoutParams;
    const View = API.View;

    // ✅ wrapper：叠放每个 tab 的 root（每个 tab 一个 ScrollView）
    const tabRootsWrapper = LinearLayout.$new(context);
    tabRootsWrapper.setOrientation(LinearLayout.VERTICAL.value);
    tabRootsWrapper.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    if (!this.tabs || this.tabs.size === 0) {
      console.warn("[FloatMenu] tabs is empty, tab container will be blank.");
    }

    let firstTabId: string | null = null;
    let firstTabInfo: any = null;

    for (const [tabId, tabInfo] of this.tabs) {
      if (!firstTabId) {
        firstTabId = tabId;
        firstTabInfo = tabInfo;
      }

      // ✅ 每个 tab 自己的 ScrollView
      const sv = ScrollView.$new(context);
      sv.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          0,
          1.0,
        ),
      );

      try {
        sv.setBackgroundColor(0x00000000);
      } catch (e) {}
      try {
        sv.setFillViewport(true);
        sv.setVerticalScrollBarEnabled(false);
      } catch (e) {}

      // ✅ 内容容器：LinearLayout（你 add row/card 都往这里加）
      const tabContainer = LinearLayout.$new(context);
      tabContainer.setOrientation(LinearLayout.VERTICAL.value);
      tabContainer.setLayoutParams(
        ViewGroupLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );

      // ✅ padding 建议放内容容器上（避免 wrapper padding 叠加）
      tabContainer.setPadding(
        dp(context, 10),
        dp(context, 10),
        dp(context, 10),
        dp(context, 10),
      );
      tabContainer.setPadding(0, 0, 0, dp(context, 4)); // 你想保留底部间距就留

      sv.addView(tabContainer);

      // ✅ 显隐：切换的是 sv
      if (tabId === this.activeTabId) {
        sv.setVisibility(View.VISIBLE.value);
        this.contentContainer = tabContainer;
        this.scrollView = sv; // ✅ 当前活跃 tab 的滚动容器
      } else {
        sv.setVisibility(View.GONE.value);
      }

      // ✅ 写回 tabInfo（关键：保持 container = 内容容器）
      tabInfo.container = tabContainer;
      tabInfo.scrollView = sv;
      tabInfo.root = sv;

      tabRootsWrapper.addView(sv);
    }

    // ✅ activeTabId 没命中 -> 默认第一个
    if (
      (!this.contentContainer || !this.scrollView) &&
      firstTabId &&
      firstTabInfo
    ) {
      this.activeTabId = firstTabId;

      if (firstTabInfo.root)
        firstTabInfo.root.setVisibility(View.VISIBLE.value);
      this.contentContainer = firstTabInfo.container;
      this.scrollView = firstTabInfo.scrollView;
    }

    // ⚠️ 这里很重要：彻底方案下，不要再 this.scrollView.addView(wrapper)
    // 你应该把 tabRootsWrapper 加到“内容区父容器”上（例如 this.rootLayout / this.mainContainer）
    this.menuContainerView.addView(tabRootsWrapper); // <- 用你的真实父容器替换
  }

  /**
   * Create tab bar view with buttons for each tab
   */
  /**
   * Create tab bar view with buttons for each tab
   */
  private createTabView(context: any): void {
    try {
      const LinearLayout = API.LinearLayout;
      const LinearLayoutParams = API.LinearLayoutParams;
      const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
      const TextView = API.TextView;
      const OnClickListener = API.OnClickListener;
      const JString = API.JString;
      const HorizontalScrollView = API.HorizontalScrollView;
      const GradientDrawable = API.GradientDrawable;
      const Gravity = API.Gravity || Java.use("android.view.Gravity");

      const self = this;

      // ===== outer scroll view =====
      const scrollView = HorizontalScrollView.$new(context);
      scrollView.setHorizontalScrollBarEnabled(false);
      scrollView.setScrollbarFadingEnabled(true);
      scrollView.setFillViewport(true); // ✅ 让内容不足时也铺满，视觉更稳定

      const scrollLp = LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      );
      scrollView.setLayoutParams(scrollLp);

      // ✅ 胶囊条背景（暗底 + 圆角 + 描边）
      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(context, 14));
      bg.setColor(DarkNeonTheme.colors.cardBg);
      bg.setStroke(dp(context, 1), DarkNeonTheme.colors.divider);
      scrollView.setBackgroundDrawable(bg);

      // 内边距（让 tab 不贴边）
      scrollView.setPadding(
        dp(context, 8),
        dp(context, 6),
        dp(context, 8),
        dp(context, 6),
      );

      // ===== inner container (tabs) =====
      const tabContainer = LinearLayout.$new(context);
      tabContainer.setOrientation(0); // HORIZONTAL
      tabContainer.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );

      // 存引用，切换 tab 时更新样式
      this.tabContainer = tabContainer;

      // ===== helper: style tab item =====
      const styleTab = (tv: any, active: boolean) => {
        // 统一字体/对齐/内边距
        tv.setAllCaps(false);
        tv.setSingleLine(true);
        tv.setGravity(Gravity.CENTER.value);
        tv.setTextSize(2, DarkNeonTheme.textSp.body);
        tv.setPadding(
          dp(context, 12),
          dp(context, 8),
          dp(context, 12),
          dp(context, 8),
        );

        // 背景：active -> 实心 accent；inactive -> 透明
        const d = GradientDrawable.$new();
        d.setCornerRadius(dp(context, 12));
        if (active) {
          d.setColor(DarkNeonTheme.colors.accent);
          tv.setTextColor(0xffffffff | 0);
        } else {
          d.setColor(0x00000000);
          tv.setTextColor(DarkNeonTheme.colors.subText);
          // 给未选中一个轻描边（可选，想更干净就删掉这行）
          d.setStroke(dp(context, 1), DarkNeonTheme.colors.divider);
        }
        tv.setBackgroundDrawable(d);

        // 选中更醒目一点
        try {
          tv.setTypeface(null, active ? 1 : 0);
        } catch (e) {}
      };

      // ===== create each tab =====
      for (const [tabId, tabInfo] of this.tabs) {
        const tabText = TextView.$new(context);
        tabText.setText(JString.$new(tabInfo.label));

        // layout params：紧凑间距
        const btnLp = LinearLayoutParams.$new(
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        );
        btnLp.setMargins(
          dp(context, 6),
          dp(context, 2),
          dp(context, 6),
          dp(context, 2),
        );
        tabText.setLayoutParams(btnLp);

        // 初始样式
        styleTab(tabText, tabId === this.activeTabId);

        // 点击切换
        const tabClickListener = Java.registerClass({
          name:
            "com.example.TabClickListener" +
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

      // ✅ 把 tabs 放进 scrollView
      scrollView.addView(tabContainer);

      // ✅ 对外暴露
      this.tabView = scrollView;

      // ✅ 你原来的 updateTabStyle 仍然能用，但建议直接在 switchTab 里调用下面这个刷新函数
      // this.refreshTabsUI();  // 可选
    } catch (error) {
      console.trace("Failed to create tab view: " + error);
    }
  }

  /**
   * Switch to a different tab
   * @param tabId ID of the tab to switch to
   */
  public switchTab(tabId: string): void {
    if (!this.tabs.has(tabId) || tabId === this.activeTabId) return;

    const oldTabId = this.activeTabId;
    this.activeTabId = tabId;
    this.refreshTabsUI();

    Java.scheduleOnMainThread(() => {
      try {
        const View = API.View;

        for (const [id, tabInfo] of this.tabs) {
          const root = tabInfo.root; // ✅ 每个 tab 的 ScrollView
          if (!root) continue;

          if (id === tabId) {
            root.setVisibility(View.VISIBLE.value);
            this.contentContainer = tabInfo.container; // ✅ LinearLayout
            this.scrollView = tabInfo.scrollView; // ✅ 当前 tab 的 ScrollView
          } else {
            root.setVisibility(View.GONE.value);
          }
        }

        if (this.tabContainer) {
          const tabIds = Array.from(this.tabs.keys());
          const childCount = this.tabContainer.getChildCount();
          for (let i = 0; i < childCount && i < tabIds.length; i++) {
            const tv = Java.cast(this.tabContainer.getChildAt(i), API.TextView);
            this.updateTabStyle(tv, tabIds[i] === tabId);
          }
        }

        this.eventEmitter.emit("tabChanged", tabId, oldTabId);
      } catch (error) {
        console.trace(`Failed to switch to tab ${tabId}:`, error);
      }
    });
  }

  /**
   * Create header view with title and subtitle
   */
  // private createHeaderView(context: any): void {
  //   try {
  //     const LinearLayout = API.LinearLayout;
  //     const LinearLayoutParams = API.LinearLayoutParams;
  //     const TextView = API.TextView;
  //     const Color = API.Color;

  //     // Create header container (vertical LinearLayout)
  //     this.headerView = LinearLayout.$new(context);
  //     const headerLayoutParams = LinearLayoutParams.$new(
  //       LinearLayoutParams.MATCH_PARENT.value,
  //       LinearLayoutParams.WRAP_CONTENT.value,
  //     );
  //     this.headerView.setOrientation(1); // VERTICAL
  //     this.headerView.setLayoutParams(headerLayoutParams);
  //     this.headerView.setPadding(16, 16, 16, 16);
  //     this.headerView.setBackgroundColor(0xff333333 | 0); // Dark gray background
  //     const JString = API.JString;
  //     // Main title
  //     const titleView = TextView.$new(context);
  //     titleView.setText(JString.$new(this.options.title || "Frida Float Menu"));
  //     titleView.setTextSize(18);
  //     titleView.setTextColor(Color.WHITE.value);
  //     titleView.setTypeface(null, 1); // Typeface.BOLD
  //     titleView.setLayoutParams(
  //       LinearLayoutParams.$new(
  //         LinearLayoutParams.MATCH_PARENT.value,
  //         LinearLayoutParams.WRAP_CONTENT.value,
  //       ),
  //     );

  //     this.headerView.addView(titleView);
  //     this.addDragListener(
  //       this.headerView,
  //       this.menuContainerView,
  //       this.menuWindowParams,
  //     );
  //   } catch (error) {
  //     console.trace("Failed to create header view: " + error);
  //   }
  // }

  // private createHeaderView(context: any): void {
  //   try {
  //     const LinearLayout = API.LinearLayout;
  //     const LinearLayoutParams = API.LinearLayoutParams;
  //     const TextView = API.TextView;
  //     const Color = API.Color;
  //     const JString = API.JString;
  //     const GradientDrawable = API.GradientDrawable;
  //     const Gravity = API.Gravity || Java.use("android.view.Gravity");

  //     // 辅助函数：创建圆形按钮
  //     function createRadiusBtn(
  //       text: string,
  //       bgColor: number,
  //       textColor: number,
  //     ) {
  //       const button = TextView.$new(context);
  //       button.setText(JString.$new(text));
  //       button.setTextSize(16); // 符号大小
  //       button.setTextColor(textColor);
  //       button.setGravity(Gravity.CENTER.value);
  //       button.setPadding(10, 10, 10, 10);

  //       // 圆形背景
  //       const drawable = GradientDrawable.$new();
  //       drawable.setCornerRadius(50); // 圆角半径 = 宽/2 得到圆形
  //       drawable.setColor(bgColor);
  //       button.setBackgroundDrawable(drawable);
  //       return button;
  //     }

  //     // 创建水平标题栏容器
  //     this.headerView = LinearLayout.$new(context);
  //     const headerLayoutParams = LinearLayoutParams.$new(
  //       LinearLayoutParams.MATCH_PARENT.value,
  //       LinearLayoutParams.WRAP_CONTENT.value,
  //     );
  //     this.headerView.setOrientation(0); // HORIZONTAL
  //     this.headerView.setLayoutParams(headerLayoutParams);
  //     this.headerView.setPadding(16, 8, 16, 8); // 垂直内边距减小
  //     this.headerView.setBackgroundColor(0xff333333 | 0);
  //     this.headerView.setGravity(Gravity.CENTER_VERTICAL.value); // 子视图垂直居中
  //     const self = this;
  //     // 左侧最小化按钮 (使用减号 "－")
  //     const minButton = createRadiusBtn("小化", 0xff555555 | 0, 0xffffffff | 0);
  //     minButton.setOnClickListener(
  //       Java.registerClass({
  //         name: "MinButtonClickListener" + Date.now(),
  //         implements: [API.OnClickListener],
  //         methods: {
  //           onClick: function (view: any) {
  //             self.isIconMode = true;
  //             self.toggleView();
  //           },
  //         },
  //       }).$new(),
  //     );

  //     // 标题（缩小字体，加粗）
  //     const titleView = TextView.$new(context);
  //     titleView.setText(JString.$new(this.options.title));
  //     titleView.setPadding(10, 10, 10, 10);

  //     titleView.setTextSize(16); // 从 18 缩小到 14
  //     titleView.setTextColor(Color.WHITE.value);
  //     titleView.setTypeface(null, 1); // BOLD
  //     titleView.setGravity(Gravity.CENTER.value);
  //     const drawable = GradientDrawable.$new();
  //     drawable.setCornerRadius(50); // 圆角半径 = 宽/2 得到圆形
  //     drawable.setColor(0xff555555 | 0);
  //     titleView.setBackgroundDrawable(drawable);
  //     // 标题占据剩余空间，实现居中
  //     const titleParams = LinearLayoutParams.$new(
  //       0,
  //       LinearLayoutParams.WRAP_CONTENT.value,
  //       1.0, // weight
  //     );
  //     titleParams.setMargins(40, 8, 40, 8);
  //     titleView.setLayoutParams(titleParams);

  //     // 右侧隐藏按钮 (使用黑色圆 "●")
  //     const hideButton = createRadiusBtn(
  //       "隐藏",
  //       0xff555555 | 0,
  //       0xffffffff | 0,
  //     );
  //     hideButton.setOnClickListener(
  //       Java.registerClass({
  //         name: "HideButtonClickListener" + Date.now(),
  //         implements: [API.OnClickListener],
  //         methods: {
  //           onClick: function (view: any) {
  //             self.isIconMode = true;
  //             self.toggleView();
  //             self.hide(); // Hide the floating window
  //             self.toast("菜单已隐藏,单击原来位置显示");
  //           },
  //         },
  //       }).$new(),
  //     );

  //     // 将所有视图添加到标题栏
  //     this.headerView.addView(minButton);
  //     this.headerView.addView(titleView);
  //     this.headerView.addView(hideButton);

  //     // 保留原有的拖动监听（如果需要调整事件冲突，可后续优化）
  //     this.addDragListener(
  //       this.headerView,
  //       this.menuContainerView,
  //       this.menuWindowParams,
  //     );
  //   } catch (error) {
  //     console.trace("Failed to create header view: " + error);
  //   }
  // }

  private createHeaderView(context: any): void {
    try {
      const LinearLayout = API.LinearLayout;
      const LinearLayoutParams = API.LinearLayoutParams;
      const TextView = API.TextView;
      const JString = API.JString;
      const GradientDrawable = API.GradientDrawable;
      const Gravity = API.Gravity || Java.use("android.view.Gravity");

      const self = this;

      const PAD_H = dp(context, 10);
      const PAD_V = dp(context, 8);
      const BTN_SIZE = dp(context, 34);
      const BTN_RADIUS = dp(context, 10);

      // 小按钮：字符 + 小方块描边（融入 header）
      const createIconCharBtn = (ch: string, isDanger = false) => {
        const btn = TextView.$new(context);
        btn.setText(JString.$new(ch));
        btn.setGravity(Gravity.CENTER.value);
        btn.setSingleLine(true);

        // 字体大小（符号稍大一点）
        btn.setTextSize(2, DarkNeonTheme.textSp.title);
        btn.setTextColor(
          isDanger ? DarkNeonTheme.colors.accent : DarkNeonTheme.colors.text,
        );

        const lp = LinearLayoutParams.$new(BTN_SIZE, BTN_SIZE);
        btn.setLayoutParams(lp);

        // 背景：透明 + 描边 + 圆角
        const d = GradientDrawable.$new();
        d.setCornerRadius(BTN_RADIUS);
        d.setColor(0x00000000);
        d.setStroke(dp(context, 1), DarkNeonTheme.colors.divider);
        btn.setBackgroundDrawable(d);

        // 点击区域 padding（主要靠 BTN_SIZE）
        btn.setPadding(
          dp(context, 6),
          dp(context, 6),
          dp(context, 6),
          dp(context, 6),
        );
        return btn;
      };

      // ===== header container =====
      this.headerView = LinearLayout.$new(context);
      this.headerView.setOrientation(0); // HORIZONTAL
      this.headerView.setGravity(Gravity.CENTER_VERTICAL.value);

      const headerLp = LinearLayoutParams.$new(
        LinearLayoutParams.MATCH_PARENT.value,
        LinearLayoutParams.WRAP_CONTENT.value,
      );
      this.headerView.setLayoutParams(headerLp);

      this.headerView.setPadding(PAD_H, PAD_V, PAD_H, PAD_V);

      // Header 背景：暗色圆角卡条
      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(context, 14));
      bg.setColor(DarkNeonTheme.colors.cardBg);
      bg.setStroke(dp(context, 1), DarkNeonTheme.colors.divider);
      this.headerView.setBackgroundDrawable(bg);

      // ===== title (LEFT) =====
      const titleView = TextView.$new(context);
      titleView.setText(JString.$new(this.options.title));
      titleView.setSingleLine(true);
      titleView.setGravity(Gravity.CENTER_VERTICAL.value);
      titleView.setTypeface(null, 1); // bold
      titleView.setTextColor(DarkNeonTheme.colors.text);
      titleView.setTextSize(2, DarkNeonTheme.textSp.title);

      // 标题占据左侧剩余空间
      const titleLp = LinearLayoutParams.$new(
        0,
        LinearLayoutParams.WRAP_CONTENT.value,
        1.0,
      );
      titleView.setLayoutParams(titleLp);
      titleView.setPadding(0, dp(context, 2), dp(context, 10), dp(context, 2));

      // ===== right buttons container =====
      const rightBox = LinearLayout.$new(context);
      rightBox.setOrientation(0);
      rightBox.setGravity(Gravity.CENTER_VERTICAL.value);

      // 右侧按钮间距
      const rightLp = LinearLayoutParams.$new(
        LinearLayoutParams.WRAP_CONTENT.value,
        LinearLayoutParams.WRAP_CONTENT.value,
      );
      rightBox.setLayoutParams(rightLp);

      // 最小化：用 “—”
      const minButton = createIconCharBtn("—", false);
      minButton.setOnClickListener(
        Java.registerClass({
          name: "MinButtonClickListener" + Date.now(),
          implements: [API.OnClickListener],
          methods: {
            onClick: function () {
              self.isIconMode = true;
              self.toggleView();
            },
          },
        }).$new(),
      );

      // 隐藏：字符按钮（这里用 👁，你想用 “×” 也可以）
      const hideButton = createIconCharBtn("X", true);
      hideButton.setOnClickListener(
        Java.registerClass({
          name: "HideButtonClickListener" + Date.now(),
          implements: [API.OnClickListener],
          methods: {
            onClick: function () {
              self.isIconMode = true;
              self.toggleView();
              self.hide();
              self.toast("菜单已隐藏,单击原来位置显示");
            },
          },
        }).$new(),
      );

      // 给右侧两个按钮一点间距
      const lpBtn = LinearLayoutParams.$new(BTN_SIZE, BTN_SIZE);
      lpBtn.setMargins(0, 0, dp(context, 8), 0);
      minButton.setLayoutParams(lpBtn);

      rightBox.addView(minButton);
      rightBox.addView(hideButton);

      // ===== assemble =====
      this.headerView.addView(titleView);
      this.headerView.addView(rightBox);

      // drag support
      this.addDragListener(
        this.headerView,
        this.menuContainerView,
        this.menuWindowParams,
      );
    } catch (error) {
      console.trace("Failed to create header view: " + error);
    }
  }
  /**
   * Create footer view with buttons
   */
  // private createFooterView(context: any): void {
  //   try {
  //     const LinearLayout = API.LinearLayout;
  //     const LinearLayoutParams = API.LinearLayoutParams;
  //     const Button = API.Button;
  //     const Color = API.Color;
  //     const OnClickListener = API.OnClickListener;

  //     // Create footer container (horizontal LinearLayout)
  //     this.footerView = LinearLayout.$new(context);
  //     this.footerView.setOrientation(0); // HORIZONTAL
  //     this.footerView.setLayoutParams(
  //       LinearLayoutParams.$new(
  //         LinearLayoutParams.MATCH_PARENT.value,
  //         LinearLayoutParams.WRAP_CONTENT.value,
  //       ),
  //     );
  //     this.footerView.setPadding(8, 8, 8, 8);
  //     this.footerView.setBackgroundColor(0xff444444 | 0); // Medium gray background

  //     const JString = API.JString;
  //     // Minimize button (switch to icon mode)
  //     const minimizeBtn = Button.$new(context);
  //     minimizeBtn.setText(JString.$new("最小化"));
  //     minimizeBtn.setTextColor(Color.WHITE.value);
  //     minimizeBtn.setBackgroundColor(0xff555555 | 0);
  //     minimizeBtn.setPadding(16, 8, 16, 8);

  //     const self = this;
  //     const minimizeListener = Java.registerClass({
  //       name:
  //         "com.example.MinimizeClickListener" +
  //         Date.now() +
  //         Math.random().toString(36).substring(6),
  //       implements: [OnClickListener],
  //       methods: {
  //         onClick: function (view: any) {
  //           self.isIconMode = true;
  //           self.toggleView();
  //         },
  //       },
  //     });
  //     minimizeBtn.setOnClickListener(minimizeListener.$new());

  //     // Hide button
  //     const hideBtn = Button.$new(context);
  //     hideBtn.setText(JString.$new("隐藏"));
  //     hideBtn.setTextColor(Color.WHITE.value);
  //     hideBtn.setBackgroundColor(0xff555555 | 0);
  //     hideBtn.setPadding(16, 8, 16, 8);

  //     const hideListener = Java.registerClass({
  //       name:
  //         "com.example.HideClickListener" +
  //         Date.now() +
  //         Math.random().toString(36).substring(6),
  //       implements: [OnClickListener],
  //       methods: {
  //         onClick: function (view: any) {
  //           self.isIconMode = true;
  //           self.toggleView();
  //           self.hide(); // Hide the floating window
  //           self.toast("菜单已隐藏,单击原来位置显示");
  //         },
  //       },
  //     });
  //     hideBtn.setOnClickListener(hideListener.$new());

  //     // Layout params for buttons
  //     const btnParams = LinearLayoutParams.$new(
  //       0, // width will be set by weight
  //       LinearLayoutParams.WRAP_CONTENT.value,
  //       1.0, // weight = 1, buttons share space equally
  //     );
  //     btnParams.setMargins(4, 0, 4, 100);

  //     minimizeBtn.setLayoutParams(btnParams);
  //     hideBtn.setLayoutParams(btnParams);

  //     this.footerView.addView(minimizeBtn);
  //     this.footerView.addView(hideBtn);
  //   } catch (error) {
  //     console.trace("Failed to create footer view: " + error);
  //   }
  // }

  /**
   * Add log message to log view
   */
  private addLogToView(level: LogLevel, message: string): void {
    const logView = this.logView;
    if (!logView) return;
    const logMaxLines = this.options.logMaxLines || 100;
    Java.scheduleOnMainThread(() => {
      const currentText = logView.getText().toString();
      const newLine = `[${level}] ${message}`;
      const lines = currentText.split("\n");
      if (lines.length >= logMaxLines) {
        lines.shift();
      }
      lines.push(newLine);
      const String = API.JString;
      logView.setText(String.$new(lines.join("\n")));
    });
  }

  /**
   * Clear log view
   */
  public clearLogs(): void {
    if (!this.logView) return;
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.logView.setText(String.$new(""));
    });
  }

  /**
   * Get the ID of the currently active tab
   */
  public getActiveTabId(): string {
    return this.activeTabId;
  }
}
