import { EventEmitter } from "./event-emitter";
import { UIComponent } from "./component/ui-components";
import { Logger, LogLevel } from "./logger";
import { API } from "./api";

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
  subtitle?: string; // Subtitle text (default: "Interactive Debugging Panel")
  showHeader?: boolean; // Whether to show header (default: true)
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
      container: any; // Content container for this tab
      components: Set<string>; // Component IDs belonging to this tab
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
      subtitle: "Interactive Debugging Panel",
      showHeader: true,
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
    const FrameLayout = API.FrameLayout;
    const LinearLayout = API.LinearLayout;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const ScrollView = API.ScrollView;
    const LinearLayoutParams = API.LinearLayoutParams;
    const View = API.View;

    // --------------------
    // 创建 menu 容器
    // --------------------
    this.menuContainerView = LinearLayout.$new(this.context);
    this.menuContainerView.setOrientation(1); // VERTICAL
    this.menuContainerView.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );
    // menuWindow 默认隐藏，由 icon 控制
    const LayoutParams = API.LayoutParams;
    this.menuWindowParams = LayoutParams.$new(
      this.options.width,
      this.options.height,
      0,
      0,
      2038, // TYPE_APPLICATION_OVERLAY
      LayoutParams.FLAG_NOT_FOCUSABLE.value |
        LayoutParams.FLAG_NOT_TOUCH_MODAL.value,
      1, // PixelFormat.TRANSLUCENT
    );

    // header
    if (this.options.showHeader) {
      this.createHeaderView(this.context);
      this.menuContainerView.addView(this.headerView);
    }

    // tab bar
    if (this.options.showTabs) {
      this.createTabView(this.context);
      this.menuContainerView.addView(this.tabView);
    }

    // scrollable content
    this.scrollView = ScrollView.$new(this.context);
    this.scrollView.setLayoutParams(
      LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, 0, 1.0),
    );

    const tabContainersWrapper = FrameLayout.$new(this.context);
    tabContainersWrapper.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    for (const [tabId, tabInfo] of this.tabs) {
      const tabContainer = LinearLayout.$new(this.context);
      tabContainer.setOrientation(1);
      tabContainer.setLayoutParams(
        ViewGroupLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );

      if (tabId === this.activeTabId) {
        tabContainer.setVisibility(View.VISIBLE.value);
        this.contentContainer = tabContainer;
      } else {
        tabContainer.setVisibility(View.GONE.value);
      }

      tabInfo.container = tabContainer;
      tabContainersWrapper.addView(tabContainer);
    }

    if (!this.contentContainer && this.tabs.size > 0) {
      const firstTab = Array.from(this.tabs.values())[0];
      this.contentContainer = firstTab.container;
      firstTab.container.setVisibility(View.VISIBLE.value);
    }

    this.scrollView.addView(tabContainersWrapper);
    this.menuContainerView.addView(this.scrollView);

    // footer
    if (this.options.showFooter) {
      this.createFooterView(this.context);
      this.menuContainerView.addView(this.footerView);
    }

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

  /**
   * Create tab bar view with buttons for each tab
   */
  private createTabView(context: any): void {
    try {
      const LinearLayout = API.LinearLayout;
      const LinearLayoutParams = API.LinearLayoutParams;
      const Button = API.Button;
      const Color = API.Color;
      const OnClickListener = API.OnClickListener;

      // Create tab bar container (horizontal LinearLayout)
      this.tabView = LinearLayout.$new(context);
      this.tabView.setOrientation(0); // HORIZONTAL
      this.tabView.setLayoutParams(
        LinearLayoutParams.$new(
          LinearLayoutParams.MATCH_PARENT.value,
          LinearLayoutParams.WRAP_CONTENT.value,
        ),
      );
      this.tabView.setPadding(8, 8, 8, 8);
      this.tabView.setBackgroundColor(0xff555555 | 0); // Medium dark gray

      const JString = API.JString;
      const self = this;

      // Create a button for each tab
      for (const [tabId, tabInfo] of this.tabs) {
        const tabButton = Button.$new(context);
        tabButton.setText(JString.$new(tabInfo.label));

        // Style active tab differently
        if (tabId === this.activeTabId) {
          tabButton.setTextColor(Color.WHITE.value);
          tabButton.setBackgroundColor(0xff4285f4 | 0); // Blue for active tab
          tabButton.setTypeface(null, 1); // Typeface.BOLD
        } else {
          tabButton.setTextColor(0xffcccccc | 0); // Light gray for inactive
          tabButton.setBackgroundColor(0xff666666 | 0); // Darker gray
        }

        tabButton.setPadding(16, 8, 16, 8);
        tabButton.setAllCaps(false);

        // Create click listener for tab button
        const tabClickListener = Java.registerClass({
          name:
            "com.example.TabClickListener" +
            Date.now() +
            Math.random().toString(36).substring(6) +
            "_" +
            tabId,
          implements: [OnClickListener],
          methods: {
            onClick: function (view: any) {
              self.switchTab(tabId);
            },
          },
        });
        tabButton.setOnClickListener(tabClickListener.$new());

        // Layout params for tab buttons (equal weight)
        const btnParams = LinearLayoutParams.$new(
          0, // width will be set by weight
          LinearLayoutParams.WRAP_CONTENT.value,
          1.0, // weight = 1, buttons share space equally
        );
        btnParams.setMargins(2, 0, 2, 0);
        tabButton.setLayoutParams(btnParams);

        this.tabView.addView(tabButton);
      }
    } catch (error) {
      console.trace("Failed to create tab view: " + error);
    }
  }

  /**
   * Switch to a different tab
   * @param tabId ID of the tab to switch to
   */
  public switchTab(tabId: string): void {
    if (!this.tabs.has(tabId) || tabId === this.activeTabId) {
      return;
    }

    const oldTabId = this.activeTabId;
    this.activeTabId = tabId;

    Java.scheduleOnMainThread(() => {
      try {
        const View = API.View;
        const Color = API.Color;
        // Update tab containers visibility
        for (const [id, tabInfo] of this.tabs) {
          if (tabInfo.container) {
            if (id === tabId) {
              tabInfo.container.setVisibility(View.VISIBLE.value);
              // Update this.contentContainer reference for backward compatibility
              this.contentContainer = tabInfo.container;
            } else {
              tabInfo.container.setVisibility(View.GONE.value);
            }
          }
        }

        // Update tab button styles if tabView exists
        if (this.tabView) {
          // Get all child buttons in tabView

          const childCount = this.tabView.getChildCount();
          for (let i = 0; i < childCount; i++) {
            // const button = this.tabView.getChildAt(i);
            const button = Java.cast(this.tabView.getChildAt(i), API.Button);
            // We need to identify which button corresponds to which tab
            // This is simplified - in a real implementation we might want to store button references
            // For now, we'll rely on the order matching the creation order
            const tabIds = Array.from(this.tabs.keys());
            if (i < tabIds.length) {
              const buttonTabId = tabIds[i];
              if (buttonTabId === tabId) {
                // Active tab style
                button.setTextColor(Color.WHITE.value);
                button.setBackgroundColor(0xff4285f4 | 0); // Blue
                // button.setTypeface(null, 1); // Bold
              } else if (buttonTabId === oldTabId) {
                // Previously active tab style
                button.setTextColor(0xffcccccc | 0); // Light gray
                button.setBackgroundColor(0xff666666 | 0); // Darker gray
              }
            }
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
  private createHeaderView(context: any): void {
    try {
      const LinearLayout = API.LinearLayout;
      const LinearLayoutParams = API.LinearLayoutParams;
      const TextView = API.TextView;
      const Color = API.Color;

      // Create header container (vertical LinearLayout)
      this.headerView = LinearLayout.$new(context);
      const headerLayoutParams = LinearLayoutParams.$new(
        LinearLayoutParams.MATCH_PARENT.value,
        LinearLayoutParams.WRAP_CONTENT.value,
      );
      this.headerView.setOrientation(1); // VERTICAL
      this.headerView.setLayoutParams(headerLayoutParams);
      this.headerView.setPadding(16, 16, 16, 16);
      this.headerView.setBackgroundColor(0xff333333 | 0); // Dark gray background
      const JString = API.JString;
      // Main title
      const titleView = TextView.$new(context);
      titleView.setText(JString.$new(this.options.title || "Frida Float Menu"));
      titleView.setTextSize(18);
      titleView.setTextColor(Color.WHITE.value);
      titleView.setTypeface(null, 1); // Typeface.BOLD
      titleView.setLayoutParams(
        LinearLayoutParams.$new(
          LinearLayoutParams.MATCH_PARENT.value,
          LinearLayoutParams.WRAP_CONTENT.value,
        ),
      );

      // Subtitle
      const subtitleView = TextView.$new(context);
      subtitleView.setText(
        JString.$new(this.options.subtitle || "Interactive Debugging Panel"),
      );
      subtitleView.setTextSize(12);
      subtitleView.setTextColor(0xffaaaaaa | 0); // Light gray
      subtitleView.setLayoutParams(
        LinearLayoutParams.$new(
          LinearLayoutParams.MATCH_PARENT.value,
          LinearLayoutParams.WRAP_CONTENT.value,
        ),
      );

      this.headerView.addView(titleView);
      this.headerView.addView(subtitleView);
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
  private createFooterView(context: any): void {
    try {
      const LinearLayout = API.LinearLayout;
      const LinearLayoutParams = API.LinearLayoutParams;
      const Button = API.Button;
      const Color = API.Color;
      const OnClickListener = API.OnClickListener;

      // Create footer container (horizontal LinearLayout)
      this.footerView = LinearLayout.$new(context);
      this.footerView.setOrientation(0); // HORIZONTAL
      this.footerView.setLayoutParams(
        LinearLayoutParams.$new(
          LinearLayoutParams.MATCH_PARENT.value,
          LinearLayoutParams.WRAP_CONTENT.value,
        ),
      );
      this.footerView.setPadding(8, 8, 8, 8);
      this.footerView.setBackgroundColor(0xff444444 | 0); // Medium gray background

      const JString = API.JString;
      // Minimize button (switch to icon mode)
      const minimizeBtn = Button.$new(context);
      minimizeBtn.setText(JString.$new("最小化"));
      minimizeBtn.setTextColor(Color.WHITE.value);
      minimizeBtn.setBackgroundColor(0xff555555 | 0);
      minimizeBtn.setPadding(16, 8, 16, 8);

      const self = this;
      const minimizeListener = Java.registerClass({
        name:
          "com.example.MinimizeClickListener" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [OnClickListener],
        methods: {
          onClick: function (view: any) {
            self.isIconMode = true;
            self.toggleView();
          },
        },
      });
      minimizeBtn.setOnClickListener(minimizeListener.$new());

      // Hide button
      const hideBtn = Button.$new(context);
      hideBtn.setText(JString.$new("隐藏"));
      hideBtn.setTextColor(Color.WHITE.value);
      hideBtn.setBackgroundColor(0xff555555 | 0);
      hideBtn.setPadding(16, 8, 16, 8);

      const hideListener = Java.registerClass({
        name:
          "com.example.HideClickListener" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [OnClickListener],
        methods: {
          onClick: function (view: any) {
            self.isIconMode = true;
            self.toggleView();
            self.hide(); // Hide the floating window
            self.toast("菜单已隐藏,单击原来位置显示");
          },
        },
      });
      hideBtn.setOnClickListener(hideListener.$new());

      // Layout params for buttons
      const btnParams = LinearLayoutParams.$new(
        0, // width will be set by weight
        LinearLayoutParams.WRAP_CONTENT.value,
        1.0, // weight = 1, buttons share space equally
      );
      btnParams.setMargins(4, 0, 4, 0);

      minimizeBtn.setLayoutParams(btnParams);
      hideBtn.setLayoutParams(btnParams);

      this.footerView.addView(minimizeBtn);
      this.footerView.addView(hideBtn);
    } catch (error) {
      console.trace("Failed to create footer view: " + error);
    }
  }

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
