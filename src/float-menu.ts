import { EventEmitter } from "./event-emitter";
import { UIComponent } from "./ui-components";
import { Logger, LogLevel } from "./logger";

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
}

export class FloatMenu {
  private options: FloatMenuOptions;
  private windowParams: any; // WindowManager.LayoutParams
  private parentContainerView: any; // Parent container (FrameLayout) holding both icon and menu
  private menuContainerView: any; // LinearLayout for menu content
  private iconView: any; // ImageView for icon
  private containerView: any; // Backward compatibility alias for parentContainerView
  private uiComponents: Map<string, UIComponent> = new Map();
  private pendingComponents: Array<{ id: string; component: UIComponent }> = [];
  private logView: any; // TextView or ListView for logs
  private eventEmitter: EventEmitter = new EventEmitter();
  private logger: Logger;
  private isShown: boolean = false;
  private isIconMode: boolean = true; // Whether currently showing icon or menu

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
      width: 600,
      height: 500,
      x: 100,
      y: 100,
      iconVisible: true,
      iconWidth: 50,
      iconHeight: 50,
      showLogs: false,
      logMaxLines: 100,
      ...options,
    };
    this.logger = new Logger(this.options.showLogs ? "debug" : "none");
    if (this.options.showLogs) {
      this.logger.on("log", (level: LogLevel, message: string) => {
        this.addLogToView(level, message);
      });
    }
    console.info("FloatMenu initialized");
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
          LayoutParams.FLAG_NOT_TOUCH_MODAL.value, // FLAG_NOT_TOUCH_MODAL
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

        // Create menu container (LinearLayout)
        const LinearLayout = Java.use("android.widget.LinearLayout");
        this.menuContainerView = LinearLayout.$new(this.context);
        this.menuContainerView.setOrientation(1); // LinearLayout.VERTICAL
        this.menuContainerView.setLayoutParams(
          ViewGroupLayoutParams.$new(
            ViewGroupLayoutParams.MATCH_PARENT.value,
            ViewGroupLayoutParams.MATCH_PARENT.value,
          ),
        );
        // Create icon view
        this.createIconView();

        // Add both views to parent container
        this.parentContainerView.addView(this.iconView);
        this.parentContainerView.addView(this.menuContainerView);

        // Set initial visibility based on iconVisible option
        const View = Java.use("android.view.View");
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
        console.info("Floating window shown");

        // Set containerView to parentContainerView for backward compatibility
        this.containerView = this.parentContainerView;

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
    for (const { id, component } of this.pendingComponents) {
      try {
        component.init(context);
        const view = component.getView();
        // Add to menu container view

        this.menuContainerView!.addView(view);

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
        console.debug(`Pending component ${id} added`);
      } catch (error) {
        console.error(`Failed to add pending component ${id}: ` + error);
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
        this.windowManager.removeView(this.containerView);
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
  public addComponent(id: string, component: UIComponent): void {
    this.uiComponents.set(id, component);

    if (!this.containerView) {
      // Window not shown yet, queue component
      this.pendingComponents.push({ id, component });
      console.debug(`Component ${id} queued (window not shown)`);
      return;
    }

    // Window is shown, add component immediately
    Java.scheduleOnMainThread(() => {
      const context = this.containerView.getContext();
      component.init(context);
      const view = component.getView();
      // Add to menu container view
      if (this.menuContainerView) {
        this.menuContainerView.addView(view);
      } else {
        // Fallback to containerView (parent) if menuContainerView not ready
        this.containerView.addView(view);
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
    console.debug(`Component ${id} added`);
  }

  /**
   * Remove a UI component
   */
  public removeComponent(id: string): void {
    const component = this.uiComponents.get(id);
    if (!component) return;
    Java.scheduleOnMainThread(() => {
      const view = component.getView();
      // Remove from menu container if it exists, otherwise from parent container
      if (this.menuContainerView) {
        try {
          this.menuContainerView.removeView(view);
        } catch (e) {
          // If not found in menu container, try parent container
          this.containerView.removeView(view);
        }
      } else {
        this.containerView.removeView(view);
      }
    });
    this.uiComponents.delete(id);
    console.debug(`Component ${id} removed`);
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
        this.containerView,
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
        this.containerView,
        this.windowParams,
      );
      // Also update container layout params
      const layoutParams = this.containerView.getLayoutParams();
      layoutParams.width = width;
      layoutParams.height = height;
      this.containerView.setLayoutParams(layoutParams);
    });
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
    // Add to menu container view
    if (this.menuContainerView) {
      this.menuContainerView.addView(this.logView);
    } else {
      // Fallback to containerView (parent) if menuContainerView not ready
      this.containerView.addView(this.logView);
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
}
