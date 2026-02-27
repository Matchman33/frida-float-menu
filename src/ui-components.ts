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
    this.view.setBackgroundColor(0xff555555 | 0); // gray background
    this.view.setPadding(16, 8, 16, 8);

    const OnClickListener = Java.use("android.view.View$OnClickListener");
    const self = this;
    const clickListener = Java.registerClass({
      name:
        "com.frida.MyClickListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
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
      name:
        "com.frida.MyCheckedChangeListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
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
    this.view.setBackgroundColor(0xff555555 | 0); // gray background

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
      this.view.setPopupBackgroundResource(0xff333333);
    } catch (e) {
      // ignore
    }
    const AdapterViewOnItemSelectedListener = Java.use(
      "android.widget.AdapterView$OnItemSelectedListener",
    );
    const self = this;

    const itemSelectedListener = Java.registerClass({
      name:
        "com.frida.MyItemSelectedListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
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

export class Slider extends UIComponent {
  private min: number;
  private max: number;
  private step: number;
  private label: string;

  constructor(
    id: string,
    label: string,
    min: number,
    max: number,
    initialValue: number = min,
    step: number = 1,
  ) {
    super(id);
    this.label = label;
    this.min = min;
    this.max = max;
    this.step = step;
    // Ensure initial value is within bounds and aligned to step
    this.value = this.clampToStep(initialValue);
  }

  protected createView(context: any): void {
    const LinearLayout = Java.use("android.widget.LinearLayout");
    const TextView = Java.use("android.widget.TextView");
    const SeekBar = Java.use("android.widget.SeekBar");
    const Color = Java.use("android.graphics.Color");
    const String = Java.use("java.lang.String");
    const ViewGroupLayoutParams = Java.use(
      "android.view.ViewGroup$LayoutParams",
    );
    const LinearLayoutParams = Java.use(
      "android.widget.LinearLayout$LayoutParams",
    );

    // Create a horizontal LinearLayout to hold label and value
    const container = LinearLayout.$new(context);
    container.setOrientation(0); // HORIZONTAL
    container.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    container.setPadding(16, 8, 16, 8);

    // Label TextView
    const labelView = TextView.$new(context);
    labelView.setText(String.$new(this.label));
    labelView.setTextColor(Color.WHITE.value);
    labelView.setTextSize(14);
    labelView.setLayoutParams(
      LinearLayoutParams.$new(
        0, // width will be set by weight
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        1.0, // weight
      ),
    );

    // Value TextView (shows current value)
    const valueView = TextView.$new(context);
    valueView.setText(String.$new(this.value.toString()));
    valueView.setTextColor(Color.WHITE.value);
    valueView.setTextSize(14);
    valueView.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    container.addView(labelView);
    container.addView(valueView);

    // SeekBar
    const seekBar = SeekBar.$new(context);
    seekBar.setMax(this.calculateSeekBarMax());
    seekBar.setProgress(this.valueToProgress(this.value));
    seekBar.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    // Create vertical layout to hold container and seekbar
    const verticalLayout = LinearLayout.$new(context);
    verticalLayout.setOrientation(1); // VERTICAL
    verticalLayout.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    verticalLayout.addView(container);
    verticalLayout.addView(seekBar);

    // Store references on the view for later updates
    this.view = verticalLayout;
    (this.view as any).seekBar = seekBar;
    (this.view as any).valueView = valueView;
    (this.view as any).labelView = labelView;
    (this.view as any).container = container;

    const SeekBarOnSeekBarChangeListener = Java.use(
      "android.widget.SeekBar$OnSeekBarChangeListener",
    );
    const self = this;

    const changeListener = Java.registerClass({
      name:
        "com.frida.MySeekBarChangeListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [SeekBarOnSeekBarChangeListener],
      methods: {
        onProgressChanged: function (
          seekBar: any,
          progress: number,
          fromUser: boolean,
        ) {
          if (fromUser) {
            const newValue = self.progressToValue(progress);
            self.value = newValue;
            // Update value display
            Java.scheduleOnMainThread(() => {
              const valueView = (self.view as any).valueView;
              if (valueView) {
                valueView.setText(String.$new(newValue.toString()));
              }
            });
            self.emit("valueChanged", newValue);
          }
        },
        onStartTrackingTouch: function (seekBar: any) {
          // Do nothing
        },
        onStopTrackingTouch: function (seekBar: any) {
          // Do nothing
        },
      },
    });
    seekBar.setOnSeekBarChangeListener(changeListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Slider:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const seekBar = (this.view as any).seekBar;
      const valueView = (this.view as any).valueView;
      if (seekBar) {
        seekBar.setProgress(this.valueToProgress(this.value));
      }
      if (valueView) {
        const String = Java.use("java.lang.String");
        valueView.setText(String.$new(this.value.toString()));
      }
    });
  }

  /**
   * Set slider label
   */
  public setLabel(label: string): void {
    this.label = label;
    if (!this.view) {
      console.warn(
        `[Slider:${this.id}] Cannot set label - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const labelView = (this.view as any).labelView;
      if (labelView) {
        const String = Java.use("java.lang.String");
        labelView.setText(String.$new(label));
      }
    });
  }

  /**
   * Set min, max, step values
   */
  public setRange(min: number, max: number, step: number = 1): void {
    this.min = min;
    this.max = max;
    this.step = step;
    this.value = this.clampToStep(this.value); // Re-clamp current value
    if (!this.view) {
      console.warn(
        `[Slider:${this.id}] Cannot set range - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const seekBar = (this.view as any).seekBar;
      if (seekBar) {
        seekBar.setMax(this.calculateSeekBarMax());
        seekBar.setProgress(this.valueToProgress(this.value));
      }
    });
    this.updateView();
  }

  // Helper methods
  private calculateSeekBarMax(): number {
    // Number of steps between min and max
    return Math.round((this.max - this.min) / this.step);
  }

  private valueToProgress(value: number): number {
    // Convert value to seekbar progress (0 to max)
    return Math.round((value - this.min) / this.step);
  }

  private progressToValue(progress: number): number {
    // Convert seekbar progress to value
    const value = this.min + progress * this.step;
    // Clamp to min/max and round to nearest step
    return this.clampToStep(value);
  }

  private clampToStep(value: number): number {
    // Clamp to [min, max] and align to step
    let clamped = Math.max(this.min, Math.min(this.max, value));
    // Round to nearest step
    if (this.step > 0) {
      const steps = Math.round((clamped - this.min) / this.step);
      clamped = this.min + steps * this.step;
    }
    return clamped;
  }
}

export class Collapsible extends UIComponent {
  private title: string;
  private expanded: boolean;
  private contentContainer: any; // LinearLayout for child components
  private arrowView: any; // ImageView for arrow icon

  constructor(id: string, title: string, expanded: boolean = false) {
    super(id);
    this.title = title;
    this.expanded = expanded;
    this.value = expanded; // Use value to store expanded state
  }

  protected createView(context: any): void {
    const LinearLayout = Java.use("android.widget.LinearLayout");
    const TextView = Java.use("android.widget.TextView");
    const ImageView = Java.use("android.widget.ImageView");
    const Color = Java.use("android.graphics.Color");
    const String = Java.use("java.lang.String");
    const ViewGroupLayoutParams = Java.use(
      "android.view.ViewGroup$LayoutParams",
    );
    const LinearLayoutParams = Java.use(
      "android.widget.LinearLayout$LayoutParams",
    );
    const View = Java.use("android.view.View");

    // Main vertical container
    const container = LinearLayout.$new(context);
    container.setOrientation(1); // VERTICAL
    container.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    container.setBackgroundColor(0xff444444 | 0); // Dark gray background
    container.setPadding(8, 8, 8, 8);

    // Title row (horizontal layout: arrow + text)
    const titleRow = LinearLayout.$new(context);
    titleRow.setOrientation(0); // HORIZONTAL
    titleRow.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    titleRow.setPadding(8, 8, 8, 8);
    titleRow.setBackgroundColor(0xff555555 | 0); // Slightly lighter gray

    // Arrow icon (ImageView)
    this.arrowView = ImageView.$new(context);
    // Create a simple arrow drawable using a triangle shape (for simplicity, we'll use text)
    // Alternatively, we can use a drawable or Unicode arrow characters
    // Using Unicode arrows: ▼ for expanded, ▶ for collapsed
    const arrowText = this.expanded ? "▼" : "▶";
    // For ImageView we need a drawable; let's use TextView for simplicity
    // Replace with proper drawable if needed
    const arrowTextView = TextView.$new(context);
    arrowTextView.setText(String.$new(arrowText));
    arrowTextView.setTextColor(Color.WHITE.value);
    arrowTextView.setTextSize(14);
    arrowTextView.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    this.arrowView = arrowTextView; // Store as arrowView

    // Title text
    const titleView = TextView.$new(context);
    titleView.setText(String.$new(this.title));
    titleView.setTextColor(Color.WHITE.value);
    titleView.setTextSize(16);
    titleView.setTypeface(null, 1); // BOLD
    titleView.setLayoutParams(
      LinearLayoutParams.$new(
        0, // width will be set by weight
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        1.0, // weight
      ),
    );

    titleRow.addView(this.arrowView);
    titleRow.addView(titleView);

    // Content container (initially visible or gone based on expanded state)
    this.contentContainer = LinearLayout.$new(context);
    this.contentContainer.setOrientation(1); // VERTICAL
    this.contentContainer.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    this.contentContainer.setPadding(16, 8, 8, 8);
    if (this.expanded) {
      this.contentContainer.setVisibility(View.VISIBLE.value);
    } else {
      this.contentContainer.setVisibility(View.GONE.value);
    }

    container.addView(titleRow);
    container.addView(this.contentContainer);

    this.view = container;

    // Store references
    (this.view as any).titleRow = titleRow;
    (this.view as any).titleView = titleView;
    (this.view as any).contentContainer = this.contentContainer;

    // Add click listener to title row
    const OnClickListener = Java.use("android.view.View$OnClickListener");
    const self = this;

    const clickListener = Java.registerClass({
      name:
        "com.frida.CollapsibleClickListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnClickListener],
      methods: {
        onClick: function (v: any) {
          self.toggle();
        },
      },
    });
    titleRow.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Collapsible:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    // Update expanded state
    this.expanded = this.value;
    Java.scheduleOnMainThread(() => {
      const View = Java.use("android.view.View");
      const String = Java.use("java.lang.String");
      const contentContainer = (this.view as any).contentContainer;
      const arrowView = this.arrowView;

      if (contentContainer) {
        if (this.expanded) {
          contentContainer.setVisibility(View.VISIBLE.value);
        } else {
          contentContainer.setVisibility(View.GONE.value);
        }
      }
      if (arrowView) {
        const arrowText = this.expanded ? "▼" : "▶";
        arrowView.setText(String.$new(arrowText));
      }
    });
  }

  /**
   * Toggle expanded/collapsed state
   */
  public toggle(): void {
    this.value = !this.value;
    this.updateView();
    this.emit("toggle", this.value);
  }

  /**
   * Expand the collapsible
   */
  public expand(): void {
    this.value = true;
    this.updateView();
    this.emit("expand");
  }

  /**
   * Collapse the collapsible
   */
  public collapse(): void {
    this.value = false;
    this.updateView();
    this.emit("collapse");
  }

  /**
   * Set title
   */
  public setTitle(title: string): void {
    this.title = title;
    if (!this.view) {
      console.warn(
        `[Collapsible:${this.id}] Cannot set title - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const titleView = (this.view as any).titleView;
      if (titleView) {
        const String = Java.use("java.lang.String");
        titleView.setText(String.$new(title));
      }
    });
  }

  /**
   * Add a child view to the content area
   * Note: This adds the view directly to the content container.
   * The child component must already be initialized.
   */
  public addChildView(view: any): void {
    if (!this.contentContainer) {
      console.warn(
        `[Collapsible:${this.id}] Cannot add child - content container not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      this.contentContainer.addView(view);
    });
  }

  /**
   * Remove a child view from the content area
   */
  public removeChildView(view: any): void {
    if (!this.contentContainer) {
      return;
    }
    Java.scheduleOnMainThread(() => {
      try {
        this.contentContainer.removeView(view);
      } catch (error) {
        // Ignore
      }
    });
  }

  /**
   * Clear all child views
   */
  public clearChildren(): void {
    if (!this.contentContainer) {
      return;
    }
    Java.scheduleOnMainThread(() => {
      this.contentContainer.removeAllViews();
    });
  }
}

export class Category extends UIComponent {
  private label: string;

  constructor(id: string, label: string) {
    super(id);
    this.label = label;
    this.value = label; // Use value to store label
  }

  protected createView(context: any): void {
    const TextView = Java.use("android.widget.TextView");
    const Color = Java.use("android.graphics.Color");
    const String = Java.use("java.lang.String");
    const LinearLayoutParams = Java.use(
      "android.widget.LinearLayout$LayoutParams",
    );
    const ViewGroupLayoutParams = Java.use(
      "android.view.ViewGroup$LayoutParams",
    );

    this.view = TextView.$new(context);
    this.view.setText(String.$new(this.label));
    this.view.setTextColor(Color.WHITE.value);
    this.view.setTextSize(16);
    this.view.setTypeface(null, 1); // BOLD
    this.view.setBackgroundColor(0xff555555 | 0); // Medium gray background
    this.view.setPadding(16, 12, 16, 12);
    this.view.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Category:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = Java.use("java.lang.String");
      this.view.setText(String.$new(this.value));
    });
  }

  /**
   * Set category label
   */
  public setLabel(label: string): void {
    this.label = label;
    this.value = label;
    this.updateView();
  }
}


