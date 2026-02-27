import { EventEmitter } from "./event-emitter";
import { UIComponent } from "./component/ui-components";
import { Logger, LogLevel } from "./logger";

export interface TabDefinition {
  id: string;
  label: string;
}

export interface FloatMenuOptions {
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  iconVisible?: boolean;
  iconWidth?: number;
  iconHeight?: number;
  iconBase64?: string; // base64 encoded icon for floating window
  showLogs?: boolean; // whether to show log panel
  logMaxLines?: number;
  activityName?: string; // optional activity class name to attach to
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
  private windowParams: any; // WindowManager.LayoutParams
  private menuContainerView: any; // Outer layout containing header, scrollable content and footer
  private contentContainer: any; // Scrollable content area (LinearLayout inside ScrollView)
  private scrollView: any; // ScrollView wrapping contentContainer
  private headerView: any; // Header area with title and subtitle
  private footerView: any; // Footer area with buttons
  private iconView: any; // ImageView for icon
  private parentContainerView: any; // Backward compatibility alias for parentContainerView
  private uiComponents: Map<string, UIComponent> = new Map();
  private pendingComponents: Array<{
    id: string;
    component: UIComponent;
    tabId: string;
  }> = [];
  private logView: any; // TextView or ListView for logs
  private eventEmitter: EventEmitter = new EventEmitter();
  private logger: Logger;
  private isShown: boolean = false;
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
      const Context = Java.use("android.content.Context");
      this._windowManager = Java.cast(
        this.context.getSystemService(Context.WINDOW_SERVICE.value),
        Java.use("android.view.ViewManager"),
      );
    }
    return this._windowManager;
  }

  constructor(options: FloatMenuOptions = {}) {
    this.options = {
      width: 1000,
      height: 900,
      x: 100,
      y: 100,
      iconVisible: true,
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
   * Create icon view
   */
  private createIconView(): void {
    try {
      const ImageView = Java.use("android.widget.ImageView");
      const ScaleType = Java.use("android.widget.ImageView$ScaleType");
      const FrameLayoutParams = Java.use(
        "android.widget.FrameLayout$LayoutParams",
      );
      const Gravity = Java.use("android.view.Gravity");

      this.iconView = ImageView.$new(this.context);

      if (this.options.iconBase64) {
        // Decode Base64 icon
        const BitmapFactory = Java.use("android.graphics.BitmapFactory");
        const Base64 = Java.use("android.util.Base64");
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
        // Create a simple colored circle as default icon
        const Color = Java.use("android.graphics.Color");
        this.iconView.setBackgroundColor(0xff4285f4 | 0); // blue color
        // Try to make it circular (requires API 21+)
        try {
          this.iconView.setClipToOutline(true);
        } catch (e) {
          // ignore if not supported
        }
      }

      this.iconView.setScaleType(ScaleType.FIT_CENTER.value);

      // Set layout params - centered in parent
      const iconSize = this.options.iconWidth || 50;
      const params = FrameLayoutParams.$new(
        iconSize,
        iconSize,
        Gravity.CENTER.value,
      );
      this.iconView.setLayoutParams(params);

      // Add click listener to toggle between icon and menu
      const OnClickListener = Java.use("android.view.View$OnClickListener");
      const self = this;

      const clickListener = Java.registerClass({
        name:
          "com.example.ClickListener" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [OnClickListener],
        methods: {
          onClick: function (view: any) {
            self.toggleView();
          },
        },
      });
      this.iconView.setOnClickListener(clickListener.$new());

      console.debug("Icon view created");
    } catch (error) {
      console.trace("Failed to create icon view: " + error);
    }
  }

  /**
   * Toggle between icon and menu view
   */
  public toggleView(): void {
    if (!this.isShown) return;

    Java.scheduleOnMainThread(() => {
      const View = Java.use("android.view.View");

      if (this.isIconMode) {
        // Currently showing icon, switch to menu
        if (this.iconView) this.iconView.setVisibility(View.GONE.value);
        if (this.menuContainerView)
          this.menuContainerView.setVisibility(View.VISIBLE.value);
        this.isIconMode = false;

        // Update window size to menu size
        this.windowParams.width = this.options.width;
        this.windowParams.height = this.options.height;
      } else {
        // Currently showing menu, switch to icon
        if (this.iconView) this.iconView.setVisibility(View.VISIBLE.value);
        if (this.menuContainerView)
          this.menuContainerView.setVisibility(View.GONE.value);
        this.isIconMode = true;

        // Update window size to icon size
        this.windowParams.width = this.options.iconWidth || 50;
        this.windowParams.height = this.options.iconHeight || 50;
      }

      // Update container layout params
      const layoutParams = this.parentContainerView.getLayoutParams();
      layoutParams.width = this.windowParams.width;
      layoutParams.height = this.windowParams.height;
      this.parentContainerView.setLayoutParams(layoutParams);

      // Update window layout
      if (this.windowManager) {
        this.windowManager.updateViewLayout(
          this.parentContainerView,
          this.windowParams,
        );
      }

      console.debug(`Switched to ${this.isIconMode ? "icon" : "menu"} mode`);
    });
  }

  /**
   * Show as icon (minimize)
   */
  public showIcon(): void {
    if (!this.isShown) return;
    Java.scheduleOnMainThread(() => {
      if (!this.isIconMode) {
        this.toggleView();
      }
    });
  }

  /**
   * Show as menu (expand)
   */
  public showMenu(): void {
    if (!this.isShown) return;
    Java.scheduleOnMainThread(() => {
      if (this.isIconMode) {
        this.toggleView();
      }
    });
  }

  /**
   * Create and show the floating window
   */
  public show(): void {
    Java.scheduleOnMainThread(() => {
      try {
        const LayoutParams = Java.use(
          "android.view.WindowManager$LayoutParams",
        );
        // Use 7-parameter constructor: (width, height, x, y, type, flags, format)
        this.windowParams = LayoutParams.$new(
          this.options.width,
          this.options.height,
          this.options.x,
          this.options.y,
          2038, // TYPE_APPLICATION_OVERLAY
          // FLAG_NOT_FOCUSABLE必须添加，防止页面卡死
          LayoutParams.FLAG_NOT_FOCUSABLE.value |
            LayoutParams.FLAG_NOT_TOUCH_MODAL.value,
          1, // PixelFormat.TRANSLUCENT
        );

        // Create parent container (FrameLayout to hold both icon and menu)
        const FrameLayout = Java.use("android.widget.FrameLayout");
        this.parentContainerView = FrameLayout.$new(this.context);
        const ViewGroupLayoutParams = Java.use(
          "android.view.ViewGroup$LayoutParams",
        );
        this.parentContainerView.setLayoutParams(
          ViewGroupLayoutParams.$new(this.options.width, this.options.height),
        );

        // Create outer layout for menu (contains header, scrollable content and footer)
        const LinearLayout = Java.use("android.widget.LinearLayout");
        const LinearLayoutParams = Java.use(
          "android.widget.LinearLayout$LayoutParams",
        );
        const ScrollView = Java.use("android.widget.ScrollView");

        // Create outer menu container (vertical LinearLayout)
        this.menuContainerView = LinearLayout.$new(this.context);
        this.menuContainerView.setOrientation(1); // LinearLayout.VERTICAL
        this.menuContainerView.setLayoutParams(
          ViewGroupLayoutParams.$new(
            ViewGroupLayoutParams.MATCH_PARENT.value,
            ViewGroupLayoutParams.MATCH_PARENT.value,
          ),
        );
        // Create and add header if enabled
        if (this.options.showHeader) {
          this.createHeaderView(this.context);

          this.menuContainerView.addView(this.headerView);
        }

        // Create and add tab bar if enabled
        if (this.options.showTabs) {
          this.createTabView(this.context);
          this.menuContainerView.addView(this.tabView);
        }

        // Create scrollable content area
        this.scrollView = ScrollView.$new(this.context);
        const scrollParams = LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          0, // height will be set by weight
          1.0, // weight = 1, takes remaining space
        );
        this.scrollView.setLayoutParams(scrollParams);

        // Create tab containers inside ScrollView
        const tabContainersWrapper = FrameLayout.$new(this.context);
        tabContainersWrapper.setLayoutParams(
          ViewGroupLayoutParams.$new(
            ViewGroupLayoutParams.MATCH_PARENT.value,
            ViewGroupLayoutParams.WRAP_CONTENT.value,
          ),
        );

        // Create a container for each tab
        const View = Java.use("android.view.View");
        for (const [tabId, tabInfo] of this.tabs) {
          const tabContainer = LinearLayout.$new(this.context);
          tabContainer.setOrientation(1); // LinearLayout.VERTICAL
          tabContainer.setLayoutParams(
            ViewGroupLayoutParams.$new(
              ViewGroupLayoutParams.MATCH_PARENT.value,
              ViewGroupLayoutParams.WRAP_CONTENT.value,
            ),
          );

          // Set visibility: only active tab is visible
          if (tabId === this.activeTabId) {
            tabContainer.setVisibility(View.VISIBLE.value);
            // Set this.contentContainer to active tab's container for backward compatibility
            this.contentContainer = tabContainer;
          } else {
            tabContainer.setVisibility(View.GONE.value);
          }

          tabInfo.container = tabContainer;
          tabContainersWrapper.addView(tabContainer);
        }

        // If no active tab found (shouldn't happen), create a default container
        if (!this.contentContainer && this.tabs.size > 0) {
          const firstTab = Array.from(this.tabs.values())[0];
          this.contentContainer = firstTab.container;
          firstTab.container.setVisibility(View.VISIBLE.value);
        }

        this.scrollView.addView(tabContainersWrapper);
        this.menuContainerView.addView(this.scrollView);

        // Create and add footer if enabled
        if (this.options.showFooter) {
          this.createFooterView(this.context);
          this.menuContainerView.addView(this.footerView);
        }
        // Create icon view
        this.createIconView();

        // Add both views to parent container
        this.parentContainerView.addView(this.iconView);
        this.parentContainerView.addView(this.menuContainerView);

        // Set initial visibility based on iconVisible option
        if (this.options.iconVisible) {
          // Show icon, hide menu
          this.iconView.setVisibility(View.VISIBLE.value);
          this.menuContainerView.setVisibility(View.GONE.value);
          this.isIconMode = true;
          // Update window size for icon
          this.windowParams.width = this.options.iconWidth || 50;
          this.windowParams.height = this.options.iconHeight || 50;
        } else {
          // Show menu, hide icon
          this.iconView.setVisibility(View.GONE.value);
          this.menuContainerView.setVisibility(View.VISIBLE.value);
          this.isIconMode = false;
          // Use full window size for menu
          this.windowParams.width = this.options.width;
          this.windowParams.height = this.options.height;
        }

        // Add log view if enabled
        if (this.options.showLogs) {
          this.createLogView(this.context);
        }

        // Add parent container to window manager
        this.windowManager.addView(this.parentContainerView, this.windowParams);
        this.isShown = true;

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

        // Add to the appropriate tab container
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
    if (!this.isShown) return;
    Java.scheduleOnMainThread(() => {
      try {
        this.windowManager.removeView(this.parentContainerView);
        this.isShown = false;
        console.info("Floating window hidden");
      } catch (error) {
        console.error("Failed to hide floating window: " + error);
      }
    });
  }

  /**
   * Add a UI component to the floating window
   * @param id Unique identifier for the component
   * @param component UI component instance
   */
  public addComponent(
    id: string,
    component: UIComponent,
    tabId?: string,
  ): void {
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

    if (!this.parentContainerView) {
      // Window not shown yet, queue component with tab info
      this.pendingComponents.push({ id, component, tabId: targetTabId });
      console.debug(
        `Component ${id} queued for tab ${targetTabId} (window not shown)`,
      );
      return;
    }

    // Window is shown, add component immediately
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
    console.debug(`Component ${id} added to tab ${targetTabId}`);
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
            if (this.menuContainerView) {
              try {
                this.menuContainerView.removeView(view);
              } catch (e2) {
                this.parentContainerView.removeView(view);
              }
            } else {
              this.parentContainerView.removeView(view);
            }
          }
        } else if (this.menuContainerView) {
          try {
            this.menuContainerView.removeView(view);
          } catch (e) {
            this.parentContainerView.removeView(view);
          }
        } else {
          this.parentContainerView.removeView(view);
        }
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
   * Update floating window position
   */
  public setPosition(x: number, y: number): void {
    if (!this.isShown) return;
    Java.scheduleOnMainThread(() => {
      this.windowParams.x = x;
      this.windowParams.y = y;
      this.windowManager.updateViewLayout(
        this.parentContainerView,
        this.windowParams,
      );
    });
  }

  /**
   * Update floating window size
   */
  public setSize(width: number, height: number): void {
    if (!this.isShown) return;
    Java.scheduleOnMainThread(() => {
      this.windowParams.width = width;
      this.windowParams.height = height;
      this.windowManager.updateViewLayout(
        this.parentContainerView,
        this.windowParams,
      );
      // Also update container layout params
      const layoutParams = this.parentContainerView.getLayoutParams();
      layoutParams.width = width;
      layoutParams.height = height;
      this.parentContainerView.setLayoutParams(layoutParams);
    });
  }

  /**
   * Create tab bar view with buttons for each tab
   */
  private createTabView(context: any): void {
    try {
      const LinearLayout = Java.use("android.widget.LinearLayout");
      const LinearLayoutParams = Java.use(
        "android.widget.LinearLayout$LayoutParams",
      );
      const Button = Java.use("android.widget.Button");
      const Color = Java.use("android.graphics.Color");
      const OnClickListener = Java.use("android.view.View$OnClickListener");

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

      const JString = Java.use("java.lang.String");
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
        const View = Java.use("android.view.View");
        const Color = Java.use("android.graphics.Color");
        const JString = Java.use("java.lang.String");
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
            const button = Java.cast(
              this.tabView.getChildAt(i),
              Java.use("android.widget.Button"),
            );
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
      const LinearLayout = Java.use("android.widget.LinearLayout");
      const LinearLayoutParams = Java.use(
        "android.widget.LinearLayout$LayoutParams",
      );
      const TextView = Java.use("android.widget.TextView");
      const Color = Java.use("android.graphics.Color");

      // Create header container (vertical LinearLayout)
      this.headerView = LinearLayout.$new(context);
      this.headerView.setOrientation(1); // VERTICAL
      this.headerView.setLayoutParams(
        LinearLayoutParams.$new(
          LinearLayoutParams.MATCH_PARENT.value,
          LinearLayoutParams.WRAP_CONTENT.value,
        ),
      );
      this.headerView.setPadding(16, 16, 16, 16);
      this.headerView.setBackgroundColor(0xff333333 | 0); // Dark gray background
      const JString = Java.use("java.lang.String");
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
    } catch (error) {
      console.trace("Failed to create header view: " + error);
    }
  }

  /**
   * Create footer view with buttons
   */
  private createFooterView(context: any): void {
    try {
      const LinearLayout = Java.use("android.widget.LinearLayout");
      const LinearLayoutParams = Java.use(
        "android.widget.LinearLayout$LayoutParams",
      );
      const Button = Java.use("android.widget.Button");
      const Color = Java.use("android.graphics.Color");
      const OnClickListener = Java.use("android.view.View$OnClickListener");

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

      const JString = Java.use("java.lang.String");
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
            self.showIcon(); // Switch to icon mode
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
            self.hide(); // Hide the floating window
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
   * Create log view (TextView) for displaying logs
   */
  private createLogView(context: any): void {
    const TextView = Java.use("android.widget.TextView");
    this.logView = TextView.$new(context);
    const LinearLayoutParams = Java.use(
      "android.widget.LinearLayout$LayoutParams",
    );
    this.logView.setLayoutParams(
      LinearLayoutParams.$new(this.options.width, 200),
    );
    this.logView.setTextSize(10);
    // this.logView.setBackgroundColor(0x80000000 | 0); // semi-transparent black as 32-bit int
    // this.logView.setTextColor(0xFFFFFFFF | 0); // white as 32-bit int
    this.logView.setMaxLines(this.options.logMaxLines);
    this.logView.setVerticalScrollBarEnabled(true);
    // Add to content container (scrollable area with other components)
    if (this.contentContainer) {
      this.contentContainer.addView(this.logView);
    } else if (this.menuContainerView) {
      // Fallback to menu container if contentContainer not available
      this.menuContainerView.addView(this.logView);
    } else {
      this.parentContainerView.addView(this.logView);
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
      const String = Java.use("java.lang.String");
      logView.setText(String.$new(lines.join("\n")));
    });
  }

  /**
   * Clear log view
   */
  public clearLogs(): void {
    if (!this.logView) return;
    Java.scheduleOnMainThread(() => {
      const String = Java.use("java.lang.String");
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
