import { EventEmitter } from "./event-emitter";

export abstract class UIComponent {
  protected emitter: EventEmitter = new EventEmitter();
  protected view: any; // Android View
  protected value: any;
  protected id: string;

  constructor(id: string) {
    this.id = id;
  }

  /**
   * Get the Android View associated with this component
   */
  public getView(): any {
    return this.view;
  }

  /**
   * Get current value of the component
   */
  public getValue(): any {
    return this.value;
  }

  /**
   * Set value and update UI
   */
  public setValue(value: any): void {
    this.value = value;
    this.updateView();
  }

  /**
   * Register event listener
   */
  public on(event: string, listener: (...args: any[]) => void): void {
    this.emitter.on(event, listener);
  }

  /**
   * Unregister event listener
   */
  public off(event: string, listener: (...args: any[]) => void): void {
    this.emitter.off(event, listener);
  }

  /**
   * Emit event
   */
  protected emit(event: string, ...args: any[]): void {
    this.emitter.emit(event, ...args);
  }

  /**
   * Abstract method to create the Android View
   */
  protected abstract createView(context: any): void;

  /**
   * Initialize the component with Android context
   */
  public init(context: any): void {
    this.createView(context);
  }

  /**
   * Abstract method to update the view when value changes
   */
  protected abstract updateView(): void;

  /**
   * Called when component is added to container
   */
  public attach(): void {
    // Override if needed
  }

  /**
   * Called when component is removed
   */
  public detach(): void {
    // Override if needed
  }
}

export class Button extends UIComponent {
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
    const String = Java.use("java.lang.String");
    const Color = Java.use("android.graphics.Color");

    this.view.setText(String.$new(this.label));
    this.view.setTextColor(Color.WHITE.value);
    this.view.setBackgroundColor(0xFF555555); // gray background
    this.view.setPadding(16, 8, 16, 8);

    const OnClickListener = Java.use("android.view.View$OnClickListener");
    const self = this;
    const clickListener = Java.registerClass({
      name: "com.frida.MyClickListener" + Date.now() + Math.random().toString(36).substring(6),
      implements: [OnClickListener],
      methods: {
        onClick: function (v) {
          self.emit("click");
          if (self.onClick) {
            self.onClick();
          }
        },
      },
    });
    this.view.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    // Button value doesn't affect UI
  }

  /**
   * Set button label
   */
  public setLabel(label: string): void {
    this.label = label;
    if (!this.view) {
      console.warn(
        `[Button:${this.id}] Cannot set label - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = Java.use("java.lang.String");
      this.view.setText(String.$new(label));
    });
  }

  /**
   * Set click handler
   */
  public setOnClick(handler: () => void): void {
    this.onClick = handler;
  }
}

export class Switch extends UIComponent {
  private label: string;

  constructor(id: string, label: string, initialValue: boolean = false) {
    super(id);
    this.label = label;
    this.value = initialValue;
  }

  protected createView(context: any): void {
    const Switch = Java.use("android.widget.Switch");
    const String = Java.use("java.lang.String");
    const Color = Java.use("android.graphics.Color");

    this.view = Switch.$new(context);
    this.view.setText(String.$new(this.label));
    this.view.setTextColor(Color.WHITE.value);
    this.view.setChecked(this.value);
    const CompoundButtonOnCheckedChangeListener = Java.use(
      "android.widget.CompoundButton$OnCheckedChangeListener",
    );
    const self = this;

    const changeListener = Java.registerClass({
      name: "com.frida.MyCheckedChangeListener" + Date.now() + Math.random().toString(36).substring(6),
      implements: [CompoundButtonOnCheckedChangeListener],
      methods: {
        onCheckedChanged: function (buttonView: any, isChecked: boolean) {
          self.value = isChecked;
          self.emit("valueChanged", isChecked);
        },
      },
    });
    this.view.setOnCheckedChangeListener(changeListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Switch:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      this.view.setChecked(this.value);
    });
  }

  /**
   * Set switch label
   */
  public setLabel(label: string): void {
    this.label = label;
    if (!this.view) {
      console.warn(
        `[Switch:${this.id}] Cannot set label - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = Java.use("java.lang.String");
      this.view.setText(String.$new(label));
    });
  }
}

export class Text extends UIComponent {
  private content: string;

  constructor(id: string, content: string) {
    super(id);
    this.content = content;
    this.value = content;
  }

  protected createView(context: any): void {
    const TextView = Java.use("android.widget.TextView");
    const Color = Java.use("android.graphics.Color");

    this.view = TextView.$new(context);
    this.view.setTextColor(Color.WHITE.value);
    this.view.setTextSize(14);
    // const String = Java.use("java.lang.String");
    // this.view.setText(String.$new(this.content));
    const Html = Java.use("android.text.Html");
    this.view.setText(Html.fromHtml(this.content));
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Text:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const Html = Java.use("android.text.Html");
      this.view.setText(Html.fromHtml(this.value));
    });
  }

  /**
   * Set text content
   */
  public setText(content: string): void {
    this.content = content;
    this.value = content;
    this.updateView();
  }
}

export class Selector extends UIComponent {
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
    const Color = Java.use("android.graphics.Color");

    this.view = Spinner.$new(context);
    this.view.setBackgroundColor(0xFF555555); // gray background

    const ArrayAdapter = Java.use("android.widget.ArrayAdapter");
    const String = Java.use("java.lang.String");
    // Convert JavaScript strings to Java strings
    const javaItems = this.items.map((item) => String.$new(item));
    // const R = Java.use("android.R");
    const R_layout = Java.use("android.R$layout");
    const adapter = ArrayAdapter.$new(
      context,
      R_layout.simple_spinner_item.value,
      Java.array("java.lang.CharSequence", javaItems),
    );
    adapter.setDropDownViewResource(
      R_layout.simple_spinner_dropdown_item.value,
    );
    this.view.setAdapter(adapter);
    this.view.setSelection(this.selectedIndex);

    // Try to set text color (may not work on all Android versions)
    try {
      this.view.setPopupBackgroundResource(0xFF333333);
    } catch (e) {
      // ignore
    }
    const AdapterViewOnItemSelectedListener = Java.use(
      "android.widget.AdapterView$OnItemSelectedListener",
    );
    const self = this;

    const itemSelectedListener = Java.registerClass({
      name: "com.frida.MyItemSelectedListener" + Date.now() + Math.random().toString(36).substring(6),
      implements: [AdapterViewOnItemSelectedListener],
      methods: {
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
      },
    });
    this.view.setOnItemSelectedListener(itemSelectedListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Selector:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    // Update selection based on value
    const index = this.items.indexOf(this.value);
    if (index !== -1) {
      Java.scheduleOnMainThread(() => {
        this.view.setSelection(index);
      });
    }
  }

  /**
   * Set selector items
   */
  public setItems(items: string[]): void {
    this.items = items;
    if (!this.view) {
      console.warn(
        `[Selector:${this.id}] Cannot set items - view not initialized`,
      );
      return;
    }
    // Update adapter
    Java.scheduleOnMainThread(() => {
      try {
        const ArrayAdapter = Java.use("android.widget.ArrayAdapter");
        const context = this.view.getContext();
        const String = Java.use("java.lang.String");
        // Convert JavaScript strings to Java strings
        const javaItems = items.map((item) => String.$new(item));
        // const R = Java.use("android.R");
        const R_layout = Java.use("android.R$layout");

        const adapter = ArrayAdapter.$new(
          context,
          R_layout.simple_spinner_item.value,
          Java.array("java.lang.CharSequence", javaItems),
        );
        adapter.setDropDownViewResource(
          R_layout.simple_spinner_dropdown_item.value,
        );
        this.view.setAdapter(adapter);
      } catch (error) {
        console.error(`[Selector:${this.id}] Failed to set items:`, error);
      }
    });
  }

  /**
   * Get selected index
   */
  public getSelectedIndex(): number {
    return this.selectedIndex;
  }
}
