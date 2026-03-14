import { EventEmitter } from "./event-emitter";
import { UIComponent } from "./component/ui-components";
import { Logger, LogLevel } from "./logger";
import { API } from "./api";
import { applyStyle, dp } from "./component/style/style";
import { DarkNeonTheme, Theme } from "./component/style/theme";
import { logicalToWindow, windowToLogical } from "./utils";
import { TabsView } from "./component/views/tabs-view";
import { HeaderView } from "./component/views/header-view";

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
  logMaxLines?: number;
  theme?: Theme;
  title?: string; // Main title text (default: "Frida Float Menu")
  tabs?: TabDefinition[]; // Tab definitions (optional)
  activeTab?: string; // Initially active tab ID (default: first tab or "default")
}

export class FloatMenu {
  public options: FloatMenuOptions;
  private headerView: any; // 标题栏容器
  private headerComponent: HeaderView;
  private iconView: any; // 图标容器
  public uiComponents: Map<string, UIComponent> = new Map();
  private pendingComponents: Array<{
    id: string;
    component: UIComponent;
    tabId: string;
  }> = [];
  private eventEmitter: EventEmitter = new EventEmitter();
  private isIconMode: boolean = true; // 当前显示图标还是菜单

  private _context: any = null;
  private lastTouchX: any;
  private lastTouchY: any;
  private screenWidth: any;
  private screenHeight: any;
  private menuWindowParams: any;
  private iconWindowParams: any;
  private iconContainerWin: any;
  private menuContainerWin: any; // 菜单界面窗口。是最底层容器

  private menuPanelView: any; // 真正用来添加组件的容器

  public logger: Logger;
  private logPanelView: any; // 用来展示日志的容器
  private tabsView: TabsView;
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
      this.options.height = Math.min(
        this.options.height!,
        this.screenHeight - 80,
      );
    });
    this.logger.info("屏幕尺寸:", this.screenWidth, this.screenHeight);

    this.headerComponent = new HeaderView(this.options.theme!);

    this.tabsView = new TabsView(
      this.context,
      this.options.theme!,
      this.options.tabs!,
      this.options.activeTab!,
    );
    // Initialize tabs
    this.tabsView.initializeTabs();
    this.logger.info("悬浮窗初始化完成,等待显示");
  }

  private addDragListener(targetView: any, window: any, winParams: any) {
    const OnTouchListener = API.OnTouchListener;
    const MotionEvent = API.MotionEvent;

    targetView.setClickable(true);
    const getBounds = () => {
      const w = this.isIconMode ? this.options.iconWidth! : this.options.width!;
      const h = this.isIconMode
        ? this.options.iconHeight!
        : this.options.height!;
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

    // 在 addDragListener 里加两个局部变量（闭包变量）
    let touchOffsetX = 0;
    let touchOffsetY = 0;
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
            case MotionEvent.ACTION_DOWN.value: {
              isDragging = false;

              const rawX = event.getRawX();
              const rawY = event.getRawY();

              // 当前窗口位置（注意：这里的 winParams.x/y 是“window坐标”）
              const startWx = winParams.x.value;
              const startWy = winParams.y.value;

              // 记录手指按下点相对窗口左上角的偏移（window坐标系内）
              touchOffsetX = rawX - startWx;
              touchOffsetY = rawY - startWy;

              // 记录 down 时的位置，用于阈值判断
              self.lastTouchX = rawX;
              self.lastTouchY = rawY;

              return true;
            }

            case MotionEvent.ACTION_MOVE.value: {
              const rawX = event.getRawX();
              const rawY = event.getRawY();

              const dx = rawX - self.lastTouchX;
              const dy = rawY - self.lastTouchY;
              if (
                !isDragging &&
                (Math.abs(dx) > DRAG_THRESHOLD || Math.abs(dy) > DRAG_THRESHOLD)
              ) {
                isDragging = true;
              }

              if (isDragging) {
                // 直接由手指位置反推窗口左上角（不会积累漂移）
                let wx = rawX - touchOffsetX;
                let wy = rawY - touchOffsetY;

                // window → logical（如果你当前还在用 logical 做边界）
                const p = windowToLogical(
                  wx,
                  wy,
                  self.screenWidth,
                  self.screenHeight,
                  self.isIconMode
                    ? self.options.iconWidth!
                    : self.options.width!,
                  self.isIconMode
                    ? self.options.iconHeight!
                    : self.options.height!,
                );
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
              // 没拖动则当点击处理（否则你 return true 会吃掉 click）
              if (!isDragging) {
                try {
                  self.isIconMode = false;

                  // 再次被点击以后设置为不透明
                  self.iconContainerWin.setAlpha(1);

                  self.toggleView();
                } catch {}
              }
              return true;
            }
          }
          // if (
          //   action === MotionEvent.ACTION_UP.value ||
          //   action === MotionEvent.ACTION_CANCEL.value
          // ) {
          //   // ✅ 如果你需要“点击”功能，这里判断：
          //   if (!isDragging) {

          //   }
          //   return true;
          // }

          // return false;
        },
      },
    });

    targetView.setOnTouchListener(touchListener.$new());
  }

  private createMenuContainerWindow() {
    const FrameLayout = API.FrameLayout;
    const LinearLayout = API.LinearLayout;
    const FrameLayoutParams = API.FrameLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const View = API.View;
    const LayoutParams = API.LayoutParams;

    // --------------------
    // 创建 window root（透明根容器）
    // --------------------
    this.menuContainerWin = FrameLayout.$new(this.context);
    const rootLp = FrameLayoutParams.$new(
      ViewGroupLayoutParams.MATCH_PARENT.value,
      ViewGroupLayoutParams.MATCH_PARENT.value,
    );
    rootLp.gravity = API.Gravity.TOP.value | API.Gravity.START.value;
    this.menuContainerWin.setLayoutParams(rootLp);

    // root 保持透明，避免灰块叠加
    try {
      this.menuContainerWin.setBackgroundColor(0x00000000);
    } catch (e) {}

    // --------------------
    // 创建 panel（真正的面板壳：背景/圆角/阴影/内边距）
    // --------------------
    const panel = LinearLayout.$new(this.context);
    panel.setOrientation(LinearLayout.VERTICAL.value);
    panel.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );

    // 用你 style.ts 的 overlay role 来统一风格
    applyStyle(panel, "overlay", this.options.theme!);

    // 可选：圆角裁剪/阴影更稳（失败就忽略）
    try {
      panel.setClipToOutline(true);
    } catch (e) {}
    try {
      panel.setClipChildren(false);
    } catch (e) {}
    try {
      panel.setClipToPadding(false);
    } catch (e) {}

    // 保存引用：以后内容都加到 panel
    this.menuPanelView = panel;

    // --------------------
    // overlayLayer（永远最上层：日志抽屉/弹窗都挂这里）
    // --------------------
    const overlay = FrameLayout.$new(this.context);
    overlay.setLayoutParams(
      FrameLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );
    // 避免裁剪 overlay
    try {
      overlay.setClipChildren(false);
    } catch (e) {}
    try {
      overlay.setClipToPadding(false);
    } catch (e) {}
    // 抬高 Z，确保压过 tab 吸顶/RecyclerView
    try {
      overlay.setElevation(100000);
    } catch (e) {}
    try {
      overlay.setTranslationZ(100000);
    } catch (e) {}
    this.logPanelView = overlay;

    // root -> panel -> overlay（overlay 必须最后 add）
    this.menuContainerWin.addView(panel);
    this.menuContainerWin.addView(overlay);

    // --------------------
    // Window 参数
    // --------------------
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

    // --------------------
    // 往 panel 里塞内容（别再塞到 menuContainerView）
    // --------------------
    this.headerView = this.headerComponent.createView(
      {
        context: this.context,
        parent: this.menuPanelView,
        logPanelView: this.logPanelView,
        height: this.options.height!,
        logMaxLines: this.options.logMaxLines,
        title: this.options.title!,
        version: "v2.4.0",
      },
      {
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
      },
    );

    if (this.headerView) {
      this.addDragListener(
        this.headerView,
        this.menuContainerWin,
        this.menuWindowParams,
      );
    }

    // tab bar
    // 不在构造函数中添加父组件是害怕父组件那时候还没初始化成功
    this.tabsView.createTabView(this.menuPanelView);
    this.tabsView.createTabContainer();

    // --------------------
    // attach window
    // --------------------
    this.windowManager.addView(this.menuContainerWin, this.menuWindowParams);
    this.menuContainerWin.setVisibility(View.GONE.value);
  }
  private updatePosition(
    window: any,
    winParams: any,
    newPos: { x: number; y: number },
  ): void {
    const { x: wx, y: wy } = logicalToWindow(
      newPos.x,
      newPos.y,
      this.screenWidth,
      this.screenHeight,
      this.isIconMode ? this.options.iconWidth! : this.options.width!,
      this.isIconMode ? this.options.iconHeight! : this.options.height!,
    );
    winParams.x.value = wx | 0;
    winParams.y.value = wy | 0;

    Java.scheduleOnMainThread(() => {
      this.windowManager.updateViewLayout(window, winParams);
    });

    // 刷新
  }

  private createIconWindow(): void {
    const ImageView = API.ImageView;
    const ImageView$ScaleType = API.ImageViewScaleType;
    const FrameLayoutParams = API.FrameLayoutParams;
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
      const bitmap = BitmapFactory.decodeByteArray(decoded, 0, decoded.length);
      this.iconView.setImageBitmap(bitmap);
    } else {
      this.iconView.setBackgroundColor(0xff4285f4 | 0);
      try {
        this.iconView.setClipToOutline(true);
      } catch {}
    }

    this.iconView.setScaleType(ImageView$ScaleType.FIT_CENTER.value);

    const { x, y } = logicalToWindow(
      this.options.x!,
      this.options.y!,
      this.screenWidth,
      this.screenHeight,
      this.options.iconWidth!,
      this.options.iconHeight!,
    );
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

    this.iconContainerWin = FrameLayout.$new(this.context);
    this.iconContainerWin.setLayoutParams(
      FrameLayoutParams.$new(
        this.options.iconWidth,
        this.options.iconHeight,
        Gravity.CENTER.value,
      ),
    );
    this.iconContainerWin.addView(this.iconView);

    // Java.scheduleOnMainThread(() => {
    // // 添加到 window manager
    this.windowManager.addView(this.iconContainerWin, this.iconWindowParams);
    // });

    this.addDragListener(
      this.iconContainerWin,
      this.iconContainerWin,
      this.iconWindowParams,
    );
  }

  /**
   * Toggle between icon and menu view
   */
  public toggleView(): void {
    Java.scheduleOnMainThread(() => {
      const View = API.View;
      if (this.isIconMode) {
        this.menuContainerWin.setVisibility(View.GONE.value);
        this.iconContainerWin.setVisibility(View.VISIBLE.value);
      } else {
        this.menuContainerWin.setVisibility(View.VISIBLE.value);
        this.iconContainerWin.setVisibility(View.GONE.value);
      }
    });
  }

  /**
   * Create and show the floating window
   */
  public show(): void {
    Java.scheduleOnMainThread(() => {
      const Settings = Java.use("android.provider.Settings");
      if (!Settings.canDrawOverlays(this.context)) {
        this.toast("进程没有悬浮窗权限!");
        Logger.instance.error("Draw overlays permission not granted");
        return;
      }
      try {
        // Create icon view
        this.createIconWindow();
        this.createMenuContainerWindow();

        // Add any pending components that were added before window was shown
        this.processPendingComponents(this.context);
      } catch (error) {
        Logger.instance.error("Failed to show floating window: ", error);
      }
    });
  }

  /**
   * Process components that were added before window was shown
   */
  // private processPendingComponents(context: any): void {
  //   if (this.pendingComponents.length === 0) return;

  //   this.logger.debug(
  //     `Processing ${this.pendingComponents.length} pending components`,
  //   );
  //   for (const { id, component, tabId } of this.pendingComponents) {
  //     try {
  //       const tabInfo = this.tabsView.tabs.get(tabId);
  //       if (!tabInfo) {
  //         this.logger.error(
  //           `Cannot add pending component ${id} - tab ${tabId} not found`,
  //         );
  //         continue;
  //       }
  //       component.init(context);

  //       const view = component.getView();
  //       // // Add to the appropriate tab container
  //       if (tabInfo.container) {
  //         tabInfo.container.addView(view);
  //       } else {
  //         // Fallback to contentContainer (should not happen if tab container was created)

  //         this.tabsView.currentContentContainer.addView(view);
  //       }

  //       // Record component ID in tab's component set
  //       tabInfo.components.add(id);

  //       // Bind events (same as in addComponent)
  //       component.on("valueChanged", (value: any) => {
  //         this.eventEmitter.emit("component:" + id + ":valueChanged", value);
  //       });
  //       component.on("action", (data: any) => {
  //         this.eventEmitter.emit("component:" + id + ":action", data);
  //       });
  //       component.on("click", (data: any) => {
  //         this.eventEmitter.emit("component:" + id + ":click", data);
  //       });
  //     } catch (error) {
  //       Logger.instance.error(
  //         `Failed to add pending component ${id}: ` + error,
  //       );
  //     }
  //   }
  //   // Clear pending components
  //   this.pendingComponents = [];
  // }

  public bindComponentEvents(component: UIComponent) {
    const id = component.getId();
    component.on("valueChanged", (value: any) => {
      this.eventEmitter.emit("component:" + id + ":valueChanged", value);
    });
    component.on("action", (data: any) => {
      this.eventEmitter.emit("component:" + id + ":action", data);
    });
    component.on("click", (data: any) => {
      this.eventEmitter.emit("component:" + id + ":click", data);
    });
  }

  private processPendingComponents(context: any): void {
    if (this.pendingComponents.length === 0) return;

    this.logger.debug(
      `Processing ${this.pendingComponents.length} pending components`,
    );

    for (const { id, component, tabId } of this.pendingComponents) {
      try {
        const tabInfo = this.tabsView.tabs.get(tabId);
        if (!tabInfo) {
          this.logger.error(
            `Cannot add pending component ${id} - tab ${tabId} not found`,
          );
          continue;
        }

        const view = this.prepareComponentView(context, component);

        if (tabInfo.container) {
          tabInfo.container.addView(view);
        } else {
          this.tabsView.currentContentContainer.addView(view);
        }

        tabInfo.components.add(id);
        this.bindComponentEvents(component);
      } catch (error) {
        Logger.instance.error(
          `Failed to add pending component ${id}: ` + error,
        );
      }
    }

    this.pendingComponents = [];
  }

  public prepareComponentView(context: any, component: any): any {
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;

    const gapNormal = dp(context, 10);

    component.init(context);

    const view = component.getView();

    const lp = LinearLayoutParams.$new(
      ViewGroupLayoutParams.MATCH_PARENT.value,
      ViewGroupLayoutParams.WRAP_CONTENT.value,
    );

    lp.setMargins(0, 0, 0, gapNormal);

    view.setLayoutParams(lp);
    return view;
  }

  /**
   * Hide and destroy the floating window
   */
  public hide(): void {
    Java.scheduleOnMainThread(() => {
      try {
        this.iconContainerWin.setAlpha(0); // 完全透明
        this.windowManager.updateViewLayout(
          this.iconContainerWin,
          this.iconWindowParams,
        );
      } catch (error) {
        Logger.instance.error("Failed to hide floating window: " + error);
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
    const targetTabId = tabId || this.tabsView.activeTabId;
    const tabInfo = this.tabsView.tabs.get(targetTabId);
    if (!tabInfo) {
      Logger.instance.error(
        `Cannot add component ${id} - tab ${targetTabId} not found`,
      );
      return;
    }

    // Store component with tab information
    this.uiComponents.set(id, component);
    component.setMenu(this);

    // Record component ID in tab's component set
    tabInfo.components.add(id);

    if (!this.menuPanelView) {
      // Window not shown yet, queue component with tab info
      this.pendingComponents.push({ id, component, tabId: targetTabId });
      Logger.instance.debug(
        `Component ${id} queued for tab ${targetTabId} (window not shown)`,
      );
      return;
    }

    // // Window is shown, add component immediately
    Java.scheduleOnMainThread(() => {
      const context = this.menuPanelView.getContext();

      // component.init(context);
      // const view = component.getView();

      const view = this.prepareComponentView(context, component);

      // Add to the appropriate tab container
      if (tabInfo.container) {
        tabInfo.container.addView(view);
      } else {
        // Fallback to contentContainer (should not happen if tab container was created)
        Logger.instance.warn(
          `Tab container for ${targetTabId} not found, using contentContainer`,
        );
        this.tabsView.currentContentContainer.addView(view);
      }

      this.bindComponentEvents(component);
      // Bind events
      // component.on("valueChanged", (value: any) => {
      //   this.eventEmitter.emit("component:" + id + ":valueChanged", value);
      // });
      // component.on("action", (data: any) => {
      //   this.eventEmitter.emit("component:" + id + ":action", data);
      // });
      // component.on("click", (data: any) => {
      //   this.eventEmitter.emit("component:" + id + ":click", data);
      // });
    });
    // Logger.instance.debug(`Component ${id} added to tab ${targetTabId}`);
  }

  /**
   * Remove a UI component
   */
  public removeComponent(id: string): void {
    const component = this.uiComponents.get(id);
    if (!component) return;

    // Find which tab this component belongs to
    let targetTabId: string | null = null;
    for (const [tabId, tabInfo] of this.tabsView.tabs) {
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
        const tabInfo = this.tabsView.tabs.get(targetTabId);
        if (tabInfo && tabInfo.container) {
          try {
            tabInfo.container.removeView(view);
          } catch (e) {
            // Fallback to contentContainer
            if (this.tabsView.currentContentContainer) {
              try {
                this.tabsView.currentContentContainer.removeView(view);
              } catch (e2) {
                // Continue to other fallbacks
              }
            }
          }
        } else if (this.tabsView.currentContentContainer) {
          // Tab container not found, try contentContainer
          try {
            this.tabsView.currentContentContainer.removeView(view);
          } catch (e) {
            // Continue to other fallbacks
          }
        }
      } else {
        // Component not associated with any tab (should not happen)
        // Use original fallback logic
        if (this.tabsView.currentContentContainer) {
          try {
            this.tabsView.currentContentContainer.removeView(view);
          } catch (e) {
            this.menuContainerWin.removeView(view);
          }
        } else if (this.menuContainerWin) {
          this.menuContainerWin.removeView(view);
        } else Logger.instance.error("error");
      }
    });

    // Remove component from tab's component set
    if (targetTabId) {
      const tabInfo = this.tabsView.tabs.get(targetTabId);
      if (tabInfo) {
        tabInfo.components.delete(id);
      }
    }

    this.uiComponents.delete(id);
    Logger.instance.debug(
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
}
