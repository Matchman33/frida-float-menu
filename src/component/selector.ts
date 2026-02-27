import { UIComponent } from "./ui-components";

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
