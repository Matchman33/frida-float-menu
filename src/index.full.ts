// Combined module for FloatMenu UI library

// === EventEmitter ===
type Listener = (...args: any[]) => void;

class EventEmitter {
  private events: Map<string, Listener[]> = new Map();

  on(event: string, listener: Listener): void {
    if (!this.events.has(event)) {
      this.events.set(event, []);
    }
    this.events.get(event)!.push(listener);
  }

  off(event: string, listener: Listener): void {
    const listeners = this.events.get(event);
    if (!listeners) return;
    const index = listeners.indexOf(listener);
    if (index !== -1) {
      listeners.splice(index, 1);
    }
  }

  emit(event: string, ...args: any[]): void {
    const listeners = this.events.get(event);
    if (!listeners) return;
    listeners.forEach((listener) => {
      try {
        listener(...args);
      } catch (error) {
        console.error(`Error in event listener for ${event}:`, error);
      }
    });
  }

  once(event: string, listener: Listener): void {
    const onceWrapper: Listener = (...args) => {
      this.off(event, onceWrapper);
      listener(...args);
    };
    this.on(event, onceWrapper);
  }

  removeAllListeners(event?: string): void {
    if (event) {
      this.events.delete(event);
    } else {
      this.events.clear();
    }
  }
}

// === Logger ===
type LogLevel = "debug" | "info" | "warn" | "error" | "none";

class Logger {
  private levelPriority: Record<LogLevel, number> = {
    debug: 0,
    info: 1,
    warn: 2,
    error: 3,
    none: 4,
  };
  private currentLevel: LogLevel;
  private emitter: any;

  constructor(level: LogLevel = "info") {
    this.currentLevel = level;
    this.emitter = {
      listeners: new Map(),
      on: function (event: string, listener: Function) {
        if (!this.listeners.has(event)) {
          this.listeners.set(event, []);
        }
        this.listeners.get(event).push(listener);
      },
      emit: function (event: string, ...args: any[]) {
        const listeners = this.listeners.get(event);
        if (!listeners) return;
        listeners.forEach((listener: Function) => {
          try {
            listener(...args);
          } catch (e) {}
        });
      },
    };
  }

  setLevel(level: LogLevel): void {
    this.currentLevel = level;
  }

  debug(message: string): void {
    this.log("debug", message);
  }

  info(message: string): void {
    this.log("info", message);
  }

  warn(message: string): void {
    this.log("warn", message);
  }

  error(message: string): void {
    this.log("error", message);
  }

  private log(level: LogLevel, message: string): void {
    if (this.levelPriority[level] < this.levelPriority[this.currentLevel]) {
      return;
    }
    const formatted = `[${level.toUpperCase()}] ${message}`;
    console.log(formatted);
    this.emitter.emit("log", level, message);
  }

  on(event: "log", listener: (level: LogLevel, message: string) => void): void {
    this.emitter.on(event, listener);
  }
}

function log(message: string): void {
  console.log(message);
}

// === UIComponent and derived classes ===
abstract class UIComponent {
  protected emitter: EventEmitter = new EventEmitter();
  protected view: any; // Android View
  protected value: any;
  protected id: string;

  constructor(id: string) {
    this.id = id;
  }

  public getView(): any {
    return this.view;
  }

  public getValue(): any {
    return this.value;
  }

  public setValue(value: any): void {
    this.value = value;
    this.updateView();
  }

  public on(event: string, listener: (...args: any[]) => void): void {
    this.emitter.on(event, listener);
  }

  public off(event: string, listener: (...args: any[]) => void): void {
    this.emitter.off(event, listener);
  }

  protected emit(event: string, ...args: any[]): void {
    this.emitter.emit(event, ...args);
  }

  protected abstract createView(context: any): void;

  public init(context: any): void {
    this.createView(context);
  }

  protected abstract updateView(): void;

  public attach(): void {
    // Override if needed
  }

  public detach(): void {
    // Override if needed
  }
}

class Button extends UIComponent {
  private label: string;
  private onClick: (() => void) | null = null;

  constructor(id: string, label: string) {
    super(id);
    this.label = label;
    this.value = null; // Buttons don't have a value
  }

  protected createView(context: any): void {
    const Button = Java.use("android.widget.Button");
    this.view = Button.$new(context);
    this.view.setText(this.label);
    const OnClickListener = Java.use("android.view.View$OnClickListener");
    const self = this;
    this.view.setOnClickListener(
      OnClickListener.$new({
        onClick: function (view: any) {
          self.emit("click");
          if (self.onClick) {
            self.onClick();
          }
        },
      }),
    );
  }

  protected updateView(): void {
    // Button value doesn't affect UI
  }

  public setLabel(label: string): void {
    this.label = label;
    Java.scheduleOnMainThread(() => {
      this.view.setText(label);
    });
  }

  public setOnClick(handler: () => void): void {
    this.onClick = handler;
  }
}

class Switch extends UIComponent {
  private label: string;

  constructor(id: string, label: string, initialValue: boolean = false) {
    super(id);
    this.label = label;
    this.value = initialValue;
  }

  protected createView(context: any): void {
    const Switch = Java.use("android.widget.Switch");
    this.view = Switch.$new(context);
    this.view.setText(this.label);
    this.view.setChecked(this.value);
    const CompoundButtonOnCheckedChangeListener = Java.use(
      "android.widget.CompoundButton$OnCheckedChangeListener",
    );
    const self = this;
    this.view.setOnCheckedChangeListener(
      CompoundButtonOnCheckedChangeListener.$new({
        onCheckedChanged: function (buttonView: any, isChecked: boolean) {
          self.value = isChecked;
          self.emit("valueChanged", isChecked);
        },
      }),
    );
  }

  protected updateView(): void {
    Java.scheduleOnMainThread(() => {
      this.view.setChecked(this.value);
    });
  }

  public setLabel(label: string): void {
    this.label = label;
    Java.scheduleOnMainThread(() => {
      this.view.setText(label);
    });
  }
}

class Text extends UIComponent {
  private content: string;

  constructor(id: string, content: string) {
    super(id);
    this.content = content;
    this.value = content;
  }

  protected createView(context: any): void {
    const TextView = Java.use("android.widget.TextView");
    this.view = TextView.$new(context);
    this.view.setText(this.content);
  }

  protected updateView(): void {
    Java.scheduleOnMainThread(() => {
      this.view.setText(this.value);
    });
  }

  public setText(content: string): void {
    this.content = content;
    this.value = content;
    this.updateView();
  }
}

class Selector extends UIComponent {
  private items: string[];
  private selectedIndex: number;

  constructor(id: string, items: string[], selectedIndex: number = 0) {
    super(id);
    this.items = items;
    this.selectedIndex = selectedIndex;
    this.value = items[selectedIndex];
  }

  protected createView(context: any): void {
    const Spinner = Java.use("android.widget.Spinner");
    this.view = Spinner.$new(context);
    const ArrayAdapter = Java.use("android.widget.ArrayAdapter");
    const adapter = ArrayAdapter.$new(
      context,
      Java.use("android.R").$new().layout.simple_spinner_item,
      Java.array("java.lang.CharSequence", this.items),
    );
    adapter.setDropDownViewResource(
      Java.use("android.R").$new().layout.simple_spinner_dropdown_item,
    );
    this.view.setAdapter(adapter);
    this.view.setSelection(this.selectedIndex);
    const AdapterViewOnItemSelectedListener = Java.use(
      "android.widget.AdapterView$OnItemSelectedListener",
    );
    const self = this;
    this.view.setOnItemSelectedListener(
      AdapterViewOnItemSelectedListener.$new({
        onItemSelected: function (
          parent: any,
          view: any,
          position: number,
          id: number,
        ) {
          self.selectedIndex = position;
          self.value = self.items[position];
          self.emit("valueChanged", self.value);
        },
        onNothingSelected: function (parent: any) {
          // Do nothing
        },
      }),
    );
  }

  protected updateView(): void {
    const index = this.items.indexOf(this.value);
    if (index !== -1) {
      Java.scheduleOnMainThread(() => {
        this.view.setSelection(index);
      });
    }
  }

  public setItems(items: string[]): void {
    this.items = items;
    Java.scheduleOnMainThread(() => {
      const ArrayAdapter = Java.use("android.widget.ArrayAdapter");
      const context = this.view.getContext();
      const adapter = ArrayAdapter.$new(
        context,
        Java.use("android.R").$new().layout.simple_spinner_item,
        Java.array("java.lang.CharSequence", items),
      );
      adapter.setDropDownViewResource(
        Java.use("android.R").$new().layout.simple_spinner_dropdown_item,
      );
      this.view.setAdapter(adapter);
    });
  }

  public getSelectedIndex(): number {
    return this.selectedIndex;
  }
}

// === FloatMenu ===
interface FloatMenuOptions {
  width?: number;
  height?: number;
  x?: number;
  y?: number;
  iconBase64?: string; // base64 encoded icon for floating window
  showLogs?: boolean; // whether to show log panel
  logMaxLines?: number;
}

class FloatMenu {
  private options: FloatMenuOptions;
  private windowManager: any; // Android WindowManager
  private windowParams: any; // WindowManager.LayoutParams
  private containerView: any; // LinearLayout or RelativeLayout
  private uiComponents: Map<string, UIComponent> = new Map();
  private logView: any; // TextView or ListView for logs
  private eventEmitter: EventEmitter = new EventEmitter();
  private logger: Logger;
  private isShown: boolean = false;

  constructor(options: FloatMenuOptions = {}) {
    this.options = {
      width: 300,
      height: 400,
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

  public show(): void {
    Java.scheduleOnMainThread(() => {
      try {
        const context = Java.use("android.app.ActivityThread")
          .currentApplication()
          .getApplicationContext();
        const Context = Java.use("android.content.Context");
        const ViewManager = Java.use("android.view.ViewManager");
        this.windowManager = Java.cast(
          context.getSystemService(Context.WINDOW_SERVICE.value),
          ViewManager,
        );

        const LayoutParams = Java.use(
          "android.view.WindowManager$LayoutParams",
        );
        this.windowParams = LayoutParams.$new();
        this.windowParams.type = LayoutParams.TYPE_APPLICATION_OVERLAY;
        this.windowParams.flags =
          LayoutParams.FLAG_NOT_FOCUSABLE | LayoutParams.FLAG_NOT_TOUCH_MODAL;
        this.windowParams.format = 1; // PixelFormat.TRANSLUCENT
        this.windowParams.width = this.options.width;
        this.windowParams.height = this.options.height;
        this.windowParams.x = this.options.x;
        this.windowParams.y = this.options.y;

        const LinearLayout = Java.use("android.widget.LinearLayout");
        this.containerView = LinearLayout.$new(context);
        this.containerView.setOrientation(LinearLayout.VERTICAL);
        const LayoutParamsClass = Java.use(
          "android.view.ViewGroup$LayoutParams",
        );
        this.containerView.setLayoutParams(
          LayoutParamsClass.$new(this.options.width, this.options.height),
        );

        if (this.options.iconBase64) {
          this.setIcon(this.options.iconBase64);
        }

        if (this.options.showLogs) {
          this.createLogView(context);
        }

        this.windowManager.addView(this.containerView, this.windowParams);
        this.isShown = true;
      } catch (error) {
        this.logger.error("Failed to show floating window: " + error);
      }
    });
  }
  

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

  public addComponent(id: string, component: UIComponent): void {
    if (!this.containerView) {
      this.logger.error("Cannot add component before floating window is shown");
      return;
    }
    this.uiComponents.set(id, component);
    Java.scheduleOnMainThread(() => {
      const context = this.containerView.getContext();
      component.init(context);
      const view = component.getView();
      this.containerView.addView(view);
      component.on("valueChanged", (value: any) => {
        this.eventEmitter.emit("component:" + id + ":valueChanged", value);
      });
      component.on("action", (data: any) => {
        this.eventEmitter.emit("component:" + id + ":action", data);
      });
      component.on("click", (data: any) => {
        this.eventEmitter.emit("component:" + id + ":action", data);
      });
    });
    this.logger.debug(`Component ${id} added`);
  }

  public removeComponent(id: string): void {
    const component = this.uiComponents.get(id);
    if (!component) return;
    Java.scheduleOnMainThread(() => {
      this.containerView.removeView(component.getView());
    });
    this.uiComponents.delete(id);
    this.logger.debug(`Component ${id} removed`);
  }

  public getComponent<T extends UIComponent>(id: string): T | undefined {
    return this.uiComponents.get(id) as T;
  }

  public setComponentValue(id: string, value: any): void {
    const component = this.uiComponents.get(id);
    if (component) {
      component.setValue(value);
    }
  }

  public on(event: string, callback: (...args: any[]) => void): void {
    this.eventEmitter.on(event, callback);
  }

  public off(event: string, callback: (...args: any[]) => void): void {
    this.eventEmitter.off(event, callback);
  }

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

  public setSize(width: number, height: number): void {
    if (!this.isShown) return;
    Java.scheduleOnMainThread(() => {
      this.windowParams.width = width;
      this.windowParams.height = height;
      this.windowManager.updateViewLayout(
        this.containerView,
        this.windowParams,
      );
      const layoutParams = this.containerView.getLayoutParams();
      layoutParams.width = width;
      layoutParams.height = height;
      this.containerView.setLayoutParams(layoutParams);
    });
  }

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
    // this.logView.setBackgroundColor(0x80000000); // semi-transparent black
    // this.logView.setTextColor(0xFFFFFFFF);
    this.logView.setMaxLines(this.options.logMaxLines || 100);
    this.logView.setVerticalScrollBarEnabled(true);
    this.containerView.addView(this.logView);
  }

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
      logView.setText(lines.join("\n"));
    });
  }

  public clearLogs(): void {
    if (!this.logView) return;
    Java.scheduleOnMainThread(() => {
      this.logView.setText("");
    });
  }
}

// Export everything
export {
  FloatMenu,
  FloatMenuOptions,
  UIComponent,
  Button,
  Switch,
  Text,
  Selector,
  Logger,
  LogLevel,
  log,
  EventEmitter,
};

// Attach to global object for easy access in Frida scripts
if (typeof globalThis !== "undefined") {
  (globalThis as any).FloatMenu = FloatMenu;
  (globalThis as any).Button = Button;
  (globalThis as any).Switch = Switch;
  (globalThis as any).Text = Text;
  (globalThis as any).Selector = Selector;
  (globalThis as any).Logger = Logger;
  (globalThis as any).EventEmitter = EventEmitter;
}
