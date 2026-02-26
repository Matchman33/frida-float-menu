import { EventEmitter } from "./event-emitter";
import { UIComponent } from "./ui-components";
import { Logger, LogLevel } from "./logger";

export interface FloatMenuOptions {
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  iconBase64?: string; // base64 encoded icon for floating window
  showLogs?: boolean; // whether to show log panel
  logMaxLines?: number;
  activityName?: string; // optional activity class name to attach to
}

export class FloatMenu {
  private options: FloatMenuOptions;
  private windowParams: any; // WindowManager.LayoutParams
  private containerView: any; // LinearLayout or RelativeLayout
  private uiComponents: Map<string, UIComponent> = new Map();
  private pendingComponents: Array<{ id: string; component: UIComponent }> = [];
  private logView: any; // TextView or ListView for logs
  private eventEmitter: EventEmitter = new EventEmitter();
  private logger: Logger;
  private isShown: boolean = false;

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
    this.logger.info("FloatMenu initialized");
  }

  /**
   * Create and show the floating window
   */
  public show(): void {
    Java.scheduleOnMainThread(async () => {
      try {
        this.logger.debug("Starting show() on main thread");
        // Get context, WindowManager and Window

        // Create LayoutParams
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

        // Create container layout
        const LinearLayout = Java.use("android.widget.LinearLayout");
        this.containerView = LinearLayout.$new(this.context);
        this.containerView.setOrientation(1); // LinearLayout.VERTICAL
        const LayoutParamsClass = Java.use(
          "android.view.ViewGroup$LayoutParams",
        );
        this.containerView.setLayoutParams(
          LayoutParamsClass.$new(this.options.width, this.options.height),
        );
        this.logger.debug("Created containerView with layout params");

        // Set icon if provided
        // Temporarily disabled due to errors
        if (this.options.iconBase64) {
          this.setIcon(this.options.iconBase64);
        }

        // Add log view if enabled
        // Temporarily disabled due to errors
        if (this.options.showLogs) {
          this.createLogView(this.context);
        }

        this.windowManager.addView(this.containerView, this.windowParams);

        this.isShown = true;
        this.logger.info("Floating window shown");

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

    this.logger.debug(
      `Processing ${this.pendingComponents.length} pending components`,
    );
    for (const { id, component } of this.pendingComponents) {
      try {
        component.init(context);
        const view = component.getView();
        this.containerView.addView(view);
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
        this.logger.debug(`Pending component ${id} added`);
      } catch (error) {
        this.logger.error(`Failed to add pending component ${id}: ` + error);
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
        this.logger.info("Floating window hidden");
      } catch (error) {
        this.logger.error("Failed to hide floating window: " + error);
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
      this.logger.debug(`Component ${id} queued (window not shown)`);
      return;
    }

    // Window is shown, add component immediately
    Java.scheduleOnMainThread(() => {
      const context = this.containerView.getContext();
      component.init(context);
      const view = component.getView();
      this.containerView.addView(view);
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
    this.logger.debug(`Component ${id} added`);
  }

  /**
   * Remove a UI component
   */
  public removeComponent(id: string): void {
    const component = this.uiComponents.get(id);
    if (!component) return;
    Java.scheduleOnMainThread(() => {
      this.containerView.removeView(component.getView());
    });
    this.uiComponents.delete(id);
    this.logger.debug(`Component ${id} removed`);
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
   * Set icon from base64 string
   */
  private setIcon(base64: string): void {
    Java.scheduleOnMainThread(() => {
      try {
        const context = this.containerView.getContext();
        const BitmapFactory = Java.use("android.graphics.BitmapFactory");
        const Base64 = Java.use("android.util.Base64");
        const decoded = Base64.decode(base64, Base64.DEFAULT);
        const bitmap = BitmapFactory.decodeByteArray(
          decoded,
          0,
          decoded.length,
        );
        // Create ImageView and set bitmap
        const ImageView = Java.use("android.widget.ImageView");
        const iconView = ImageView.$new(context);
        iconView.setImageBitmap(bitmap);
        const LinearLayoutParams = Java.use(
          "android.widget.LinearLayout$LayoutParams",
        );
        iconView.setLayoutParams(LinearLayoutParams.$new(50, 50));
        this.containerView.addView(iconView, 0);
      } catch (error) {
        this.logger.error("Failed to set icon: " + error);
      }
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
    this.containerView.addView(this.logView);
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
