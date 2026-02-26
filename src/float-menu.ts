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
  backgroundColor?: number; // background color (ARGB format, e.g., 0xFF202020)
  title?: string; // main title text
  subtitle?: string; // subtitle text
  iconMode?: boolean; // start as icon, expand on click
  defaultExpanded?: boolean; // if iconMode is true, start expanded?
}

export class FloatMenu {
  private options: FloatMenuOptions;
  private windowManager: any; // Android WindowManager
  private windowParams: any; // WindowManager.LayoutParams
  private containerView: any; // LinearLayout or RelativeLayout
  private uiComponents: Map<string, UIComponent> = new Map();
  private pendingComponents: Array<{ id: string; component: UIComponent }> = [];
  private logView: any; // TextView or ListView for logs
  private eventEmitter: EventEmitter = new EventEmitter();
  private logger: Logger;
  private isShown: boolean = false;
  private wmGlobal: any; // WindowManagerGlobal instance
  private titleView: any; // TextView for title
  private subtitleView: any; // TextView for subtitle
  private iconView: any; // ImageView for icon mode
  private titleBarLayout: any; // Layout for title bar
  private buttonBarLayout: any; // Layout for minimize/hide buttons
  private contentLayout: any; // Layout for menu content
  private isExpanded: boolean = true; // Whether menu is expanded (vs icon mode)

  constructor(options: FloatMenuOptions = {}) {
    this.options = {
      width: 300,
      height: 400,
      x: 100,
      y: 100,
      showLogs: false,
      logMaxLines: 100,
      backgroundColor: 0xff202020, // dark gray background
      title: "Float Menu",
      subtitle: "",
      iconMode: false,
      defaultExpanded: true,
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

  private findActivity(name: string): Promise<any | null> {
    return new Promise((resolve) => {
      let result: any = null;
      Java.choose(name, {
        onMatch(instance) {
          result = instance;
          return "stop";
        },
        onComplete() {
          resolve(result);
        },
      });
    });
  }

  /**
   * Create title bar with main title and subtitle
   */
  private createTitleBar(context: any): void {
    const LinearLayout = Java.use("android.widget.LinearLayout");
    const TextView = Java.use("android.widget.TextView");
    const String = Java.use("java.lang.String");
    const Color = Java.use("android.graphics.Color");

    // Title bar layout (vertical)
    this.titleBarLayout = LinearLayout.$new(context);
    this.titleBarLayout.setOrientation(1); // VERTICAL
    const titleBarParams = Java.use("android.view.ViewGroup$LayoutParams").$new(
      Java.use("android.view.ViewGroup$LayoutParams").MATCH_PARENT,
      80, // height in pixels
    );
    this.titleBarLayout.setLayoutParams(titleBarParams);
    this.titleBarLayout.setBackgroundColor(0xff303030); // dark gray
    this.titleBarLayout.setPadding(16, 8, 16, 8);

    // Main title
    this.titleView = TextView.$new(context);
    this.titleView.setText(String.$new(this.options.title || "Float Menu"));
    this.titleView.setTextSize(18);
    this.titleView.setTextColor(Color.WHITE.value);
    this.titleView.setTypeface(null, 1); // Typeface.BOLD
    const titleParams = Java.use("android.view.ViewGroup$LayoutParams").$new(
      Java.use("android.view.ViewGroup$LayoutParams").MATCH_PARENT,
      Java.use("android.view.ViewGroup$LayoutParams").WRAP_CONTENT,
    );
    this.titleView.setLayoutParams(titleParams);

    // Subtitle
    this.subtitleView = TextView.$new(context);
    this.subtitleView.setText(String.$new(this.options.subtitle || ""));
    this.subtitleView.setTextSize(12);
    this.subtitleView.setTextColor(0xffaaaaaa);
    const subtitleParams = Java.use("android.view.ViewGroup$LayoutParams").$new(
      Java.use("android.view.ViewGroup$LayoutParams").MATCH_PARENT,
      Java.use("android.view.ViewGroup$LayoutParams").WRAP_CONTENT,
    );
    this.subtitleView.setLayoutParams(subtitleParams);
    this.subtitleView.setPadding(0, 4, 0, 0);

    // Add views to title bar
    this.titleBarLayout.addView(this.titleView);
    this.titleBarLayout.addView(this.subtitleView);

    // Add title bar to container
    this.containerView.addView(this.titleBarLayout);
  }

  /**
   * Create content layout for UI components
   */
  private createContentLayout(context: any): void {
    const LinearLayout = Java.use("android.widget.LinearLayout");

    this.contentLayout = LinearLayout.$new(context);
    this.contentLayout.setOrientation(1); // VERTICAL
    const contentParams = Java.use("android.view.ViewGroup$LayoutParams").$new(
      Java.use("android.view.ViewGroup$LayoutParams").MATCH_PARENT,
      Java.use("android.view.ViewGroup$LayoutParams").WRAP_CONTENT,
    );
    this.contentLayout.setLayoutParams(contentParams);
    this.contentLayout.setPadding(16, 16, 16, 16);

    // Add content layout to container
    this.containerView.addView(this.contentLayout);
  }

  /**
   * Create button bar with minimize and hide buttons
   */
  private createButtonBar(context: any): void {
    const LinearLayout = Java.use("android.widget.LinearLayout");
    const Button = Java.use("android.widget.Button");
    const String = Java.use("java.lang.String");
    const Color = Java.use("android.graphics.Color");

    // Button bar layout (horizontal)
    this.buttonBarLayout = LinearLayout.$new(context);
    this.buttonBarLayout.setOrientation(0); // HORIZONTAL
    const buttonBarParams = Java.use(
      "android.view.ViewGroup$LayoutParams",
    ).$new(
      Java.use("android.view.ViewGroup$LayoutParams").MATCH_PARENT,
      60, // height in pixels
    );
    this.buttonBarLayout.setLayoutParams(buttonBarParams);
    this.buttonBarLayout.setBackgroundColor(0xff252525);
    this.buttonBarLayout.setPadding(16, 8, 16, 8);
    this.buttonBarLayout.setGravity(17); // Gravity.CENTER

    // Minimize button
    const minimizeButton = Button.$new(context);
    minimizeButton.setText(String.$new("最小化"));
    minimizeButton.setTextColor(Color.WHITE.value);
    minimizeButton.setBackgroundColor(0xff555555);
    const minimizeParams = Java.use(
      "android.widget.LinearLayout$LayoutParams",
    ).$new(
      0, // width
      Java.use("android.view.ViewGroup$LayoutParams").WRAP_CONTENT,
    );
    minimizeParams.weight = 1;
    minimizeParams.setMargins(0, 0, 8, 0);
    minimizeButton.setLayoutParams(minimizeParams);

    // Hide button
    const hideButton = Button.$new(context);
    hideButton.setText(String.$new("隐藏"));
    hideButton.setTextColor(Color.WHITE.value);
    hideButton.setBackgroundColor(0xffaa3333);
    const hideParams = Java.use(
      "android.widget.LinearLayout$LayoutParams",
    ).$new(
      0, // width
      Java.use("android.view.ViewGroup$LayoutParams").WRAP_CONTENT,
    );
    hideParams.weight = 1;
    hideParams.setMargins(8, 0, 0, 0);
    hideButton.setLayoutParams(hideParams);

    // Add click listeners
    const OnClickListener = Java.use("android.view.View$OnClickListener");
    const self = this;

    const minimizeListener = OnClickListener.implement({
      onClick: function (view: any) {
        self.minimize();
      },
    });
    minimizeButton.setOnClickListener(minimizeListener);

    const hideListener = OnClickListener.implement({
      onClick: function (view: any) {
        self.hide();
      },
    });
    hideButton.setOnClickListener(hideListener);

    // Add buttons to button bar
    this.buttonBarLayout.addView(minimizeButton);
    this.buttonBarLayout.addView(hideButton);

    // Add button bar to container
    this.containerView.addView(this.buttonBarLayout);
  }

  /**
   * Create icon view for icon mode
   */
  private createIconView(context: any): void {
    const ImageView = Java.use("android.widget.ImageView");
    const Bitmap = Java.use("android.graphics.Bitmap");
    const BitmapFactory = Java.use("android.graphics.BitmapFactory");
    const Base64 = Java.use("android.util.Base64");
    const Canvas = Java.use("android.graphics.Canvas");
    const Paint = Java.use("android.graphics.Paint");
    const Rect = Java.use("android.graphics.Rect");
    const RectF = Java.use("android.graphics.RectF");

    this.iconView = ImageView.$new(context);

    // icon size (px)
    const size = 60;

    // LayoutParams
    const ViewGroupLayoutParams = Java.use(
      "android.view.ViewGroup$LayoutParams",
    );
    this.iconView.setLayoutParams(ViewGroupLayoutParams.$new(size, size));

    this.iconView.setScaleType(ImageView.ScaleType.CENTER_CROP.value);

    let bitmap = null;

    /* ===============================
     * 1️⃣ Base64 → Bitmap
     * =============================== */
    if (this.options.iconBase64) {
      try {
        const bytes = Base64.decode(
          this.options.iconBase64,
          Base64.DEFAULT.value,
        );

        bitmap = BitmapFactory.decodeByteArray(bytes, 0, bytes.length);
      } catch (e: any) {
        console.trace("Failed to decode iconBase64:", e);
      }
    }

    /* ===============================
     * 2️⃣ fallback：生成纯色圆形 icon
     * =============================== */
    if (!bitmap) {
      bitmap = Bitmap.createBitmap(size, size, Bitmap.Config.ARGB_8888.value);

      const canvas = Canvas.$new(bitmap);
      const paint = Paint.$new();
      paint.setAntiAlias(true);
      paint.setColor(0xff4285f4); // Blue

      canvas.drawCircle(size / 2, size / 2, size / 2, paint);
    }

    /* ===============================
     * 3️⃣ 裁剪成圆形（通用）
     * =============================== */
    const output = Bitmap.createBitmap(
      size,
      size,
      Bitmap.Config.ARGB_8888.value,
    );

    const canvas = Canvas.$new(output);
    const paint = Paint.$new();
    paint.setAntiAlias(true);

    const rect = Rect.$new(0, 0, size, size);
    const rectF = RectF.$new(rect);

    canvas.drawOval(rectF, paint);
    paint.setXfermode(
      Java.use("android.graphics.PorterDuffXfermode").$new(
        Java.use("android.graphics.PorterDuff$Mode").SRC_IN.value,
      ),
    );

    canvas.drawBitmap(bitmap, rect, rect, paint);

    // 设置到 ImageView
    this.iconView.setImageBitmap(output);

    /* ===============================
     * 4️⃣ FrameLayout 居中
     * =============================== */
    const FrameLayoutParams = Java.use(
      "android.widget.FrameLayout$LayoutParams",
    );

    const Gravity = Java.use("android.view.Gravity");

    this.iconView.setLayoutParams(
      FrameLayoutParams.$new(size, size, Gravity.CENTER.value),
    );

    // Add click listener to toggle expand/collapse
    const OnClickListener = Java.use("android.view.View$OnClickListener");
    const self = this;
    // const iconClickListener = OnClickListener.implement({
    //   onClick: function (view: any) {
    //     self.toggleExpand();
    //   },
    // });

    const clickListener = Java.registerClass({
      // 动态生成类名，避免重复注册导致 ART 报错
      name:
        "com.frida.ImageViewClick_" + Math.random().toString(36).substring(7),
      implements: [OnClickListener],
      methods: {
        onClick: function (view) {
          // 调用你的方法
          self.toggleExpand();

          // 可选：打印日志
          console.log("Icon clicked!");
        },
      },
    });

    // 绑定到 ImageView
    this.iconView.setOnClickListener(clickListener.$new());
  }

  /**
   * Toggle between expanded and icon mode
   */
  public toggleExpand(): void {
    if (!this.isShown) return;

    Java.scheduleOnMainThread(() => {
      this.isExpanded = !this.isExpanded;
      this.updateLayoutVisibility();
    });
  }

  /**
   * Minimize to icon mode
   */
  public minimize(): void {
    if (!this.isShown) return;

    Java.scheduleOnMainThread(() => {
      this.isExpanded = false;
      this.updateLayoutVisibility();
    });
  }

  /**
   * Update visibility of layout components based on expansion state
   */
  private updateLayoutVisibility(): void {
    if (!this.containerView) return;

    const View = Java.use("android.view.View");

    if (this.isExpanded) {
      // Show full menu
      if (this.titleBarLayout)
        this.titleBarLayout.setVisibility(View.VISIBLE.value);
      if (this.contentLayout)
        this.contentLayout.setVisibility(View.VISIBLE.value);
      if (this.buttonBarLayout)
        this.buttonBarLayout.setVisibility(View.VISIBLE.value);
      if (this.iconView) this.iconView.setVisibility(View.GONE.value);

      // Update window size to expanded size
      this.windowParams.width = this.options.width || 300;
      this.windowParams.height = this.options.height || 400;
    } else {
      // Show only icon
      if (this.titleBarLayout)
        this.titleBarLayout.setVisibility(View.GONE.value);
      if (this.contentLayout) this.contentLayout.setVisibility(View.GONE.value);
      if (this.buttonBarLayout)
        this.buttonBarLayout.setVisibility(View.GONE.value);
      if (this.iconView) this.iconView.setVisibility(View.VISIBLE.value);

      // Update window size to icon size
      this.windowParams.width = 80;
      this.windowParams.height = 80;
    }

    // Update container view layout params
    const layoutParams = this.containerView.getLayoutParams();
    layoutParams.width = this.windowParams.width;
    layoutParams.height = this.windowParams.height;
    this.containerView.setLayoutParams(layoutParams);

    // Update window layout
    if (this.windowManager) {
      this.windowManager.updateViewLayout(
        this.containerView,
        this.windowParams,
      );
    }
  }

  /**
   * Create and show the floating window
   */
  public show(): void {
    Java.scheduleOnMainThread(async () => {
      try {
        this.logger.debug("Starting show() on main thread");
        // Get context, WindowManager and Window
        let context,
          windowManager,
          window = null;

        if (this.options.activityName) {
          // Try to find activity by name
          this.logger.debug(
            `Looking for activity: ${this.options.activityName}`,
          );
          try {
            // Java.choose to find activity instances
            const foundActivity = await this.findActivity(
              this.options.activityName,
            );

            if (foundActivity) {
              context = foundActivity;
              windowManager = foundActivity.getWindowManager();
              window = foundActivity.getWindow();
              this.logger.debug(
                `Got windowManager and window from activity: ${this.options.activityName}`,
              );
            } else {
              this.logger.debug(
                `Activity ${this.options.activityName} not found, using application context`,
              );
              // Fallback to application context
              const ActivityThread = Java.use("android.app.ActivityThread");
              context =
                ActivityThread.currentApplication().getApplicationContext();
              const windowService = context.getSystemService("window");
              const WindowManagerInterface = Java.use(
                "android.view.WindowManager",
              );
              windowManager = Java.cast(windowService, WindowManagerInterface);
              // window remains null
            }
          } catch (activityError) {
            this.logger.debug(
              `Failed to get activity ${this.options.activityName}: ${activityError}, using application context`,
            );
            const ActivityThread = Java.use("android.app.ActivityThread");
            context =
              ActivityThread.currentApplication().getApplicationContext();
            const windowService = context.getSystemService("window");
            const WindowManagerInterface = Java.use(
              "android.view.WindowManager",
            );
            windowManager = Java.cast(windowService, WindowManagerInterface);
            // window remains null
          }
        } else {
          // No activity name specified, use application context
          const ActivityThread = Java.use("android.app.ActivityThread");
          context = ActivityThread.currentApplication().getApplicationContext();
          const windowService = context.getSystemService("window");
          const WindowManagerInterface = Java.use("android.view.WindowManager");
          windowManager = Java.cast(windowService, WindowManagerInterface);
          this.logger.debug("Got windowManager from application context");
          // window remains null
        }
        this.windowManager = windowManager;

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
        this.containerView = LinearLayout.$new(context);
        this.containerView.setOrientation(1); // LinearLayout.VERTICAL
        const LayoutParamsClass = Java.use(
          "android.view.ViewGroup$LayoutParams",
        );
        this.containerView.setLayoutParams(
          LayoutParamsClass.$new(this.options.width, this.options.height),
        );

        // Set background color
        if (this.options.backgroundColor !== undefined) {
          const Color = Java.use("android.graphics.Color");
          this.containerView.setBackgroundColor(this.options.backgroundColor);
        }

        this.logger.debug("Created containerView with layout params");

        // Create title bar
        this.createTitleBar(context);

        // Create content layout for UI components
        this.createContentLayout(context);

        // Create button bar with minimize and hide buttons
        this.createButtonBar(context);

        // Create icon view for icon mode
        this.createIconView(context);
        if (this.iconView) {
          this.containerView.addView(this.iconView);
        }

        // Set initial expansion state
        this.isExpanded =
          !this.options.iconMode! || this.options.defaultExpanded!;
        this.updateLayoutVisibility();

        // Set icon if provided
        // Temporarily disabled due to errors
        if (this.options.iconBase64) {
            this.setIcon(this.options.iconBase64);
        }

        // Add log view if enabled
        // Temporarily disabled due to errors
        if (this.options.showLogs) {
            this.createLogView(context);
        }

        // Add container to window using WindowManagerGlobal
        this.logger.debug("Using WindowManagerGlobal for overlay window");

        const WindowManagerGlobal = Java.use(
          "android.view.WindowManagerGlobal",
        );
        const wmGlobal = WindowManagerGlobal.getInstance();
        this.wmGlobal = wmGlobal; // Store WindowManagerGlobal instance

        // Get display
        const display = windowManager.getDefaultDisplay();
        this.logger.debug("Got display: " + display.$className);

        // Use window obtained earlier, or try to get from context if still null
        if (window === null && context.getWindow) {
          try {
            window = context.getWindow();
            this.logger.debug(
              "Got window from context: " +
                (window ? window.$className : "null"),
            );
          } catch (e) {
            this.logger.debug("Cannot get window from context: " + e);
          }
        }

        // User ID (0 for current user)
        const userId = 0;

        if (window !== null) {
          this.logger.debug(
            "Calling WindowManagerGlobal.addView with 5 parameters",
          );
          this.logger.debug(
            `display: ${display ? display.$className : "null"}, window: ${window.$className}, userId: ${userId}`,
          );
          wmGlobal.addView(
            this.containerView,
            this.windowParams,
            display,
            window,
            userId,
          );
        } else {
          this.logger.debug(
            "Window is null, falling back to windowManager.addView with 2 parameters",
          );
          try {
            windowManager.addView(this.containerView, this.windowParams);
            this.logger.debug("windowManager.addView succeeded");
          } catch (e) {
            this.logger.error("windowManager.addView failed: " + e);
            // Re-throw to be caught by outer try-catch
            throw e;
          }
        }
        this.isShown = true;
        this.logger.info("Floating window shown");

        // Add any pending components that were added before window was shown
        this.processPendingComponents(context);
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
        // Add to content layout instead of container
        if (this.contentLayout) {
          this.contentLayout.addView(view);
        } else {
          this.containerView.addView(view);
        }
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
        // Use WindowManagerGlobal to remove view
        if (this.wmGlobal) {
          this.wmGlobal.removeView(this.containerView, false); // false = not immediate
        } else {
          // Fallback to original windowManager
          this.windowManager.removeView(this.containerView);
        }
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
      // Add to content layout instead of container
      if (this.contentLayout) {
        this.contentLayout.addView(view);
      } else {
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
