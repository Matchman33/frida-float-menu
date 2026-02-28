import { API } from "../api";
import { UIComponent } from "./ui-components";

export class Selector extends UIComponent {
  private items: { lable: string; [key: string]: any }[];
  private selectedIndex: number;
  private handler?: (value: any) => {};

  constructor(
    id: string,
    items: { lable: string; [key: string]: any }[],
    selectedIndex: number = 0,
  ) {
    super(id);
    this.items = items;
    this.selectedIndex = selectedIndex;
    this.value = items[selectedIndex];
  }

  protected createView(context: any): void {
    const Spinner = API.Spinner;
    const ArrayAdapter = API.ArrayAdapter;
    const String = API.JString;
    const R_layout = API.R_layout;
    this.button = Spinner.$new(context);
    this.button.setBackgroundColor(0xff555555 | 0); // gray background

    // Convert JavaScript strings to Java strings
    const javaItems = this.items.map((item) => String.$new(item.lable));
    // const R = Java.use("android.R");

    const adapter = ArrayAdapter.$new(
      context,
      R_layout.simple_spinner_item.value,
      Java.array("java.lang.CharSequence", javaItems),
    );
    adapter.setDropDownViewResource(
      R_layout.simple_spinner_dropdown_item.value,
    );
    this.button.setAdapter(adapter);
    this.button.setSelection(this.selectedIndex);

    // Try to set text color (may not work on all Android versions)
    try {
      this.button.setPopupBackgroundResource(0xff333333);
    } catch (e) {
      // ignore
    }
    const AdapterViewOnItemSelectedListener =
      API.AdapterViewOnItemSelectedListener;
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
          if (self.handler) setImmediate(() => self.handler!(self.value));
        },
        onNothingSelected: function (parent: any) {
          // Do nothing
        },
      },
    });
    this.button.setOnItemSelectedListener(itemSelectedListener.$new());
  }

  public onValueChange(handler: (value: any) => {}) {
    this.handler = handler;
  }

  protected updateView(): void {
    if (!this.button) {
      console.warn(
        `[Selector:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    // Update selection based on value

    const index = this.items.findIndex(
      (value) => value.lable == this.value.lable,
    );
    if (index !== -1) {
      Java.scheduleOnMainThread(() => {
        this.button.setSelection(index);
      });
    }
  }

  /**
   * Set selector items
   */
  public setItems(items: { lable: string; [key: string]: any }[]): void {
    this.items = items;
    if (!this.button) {
      console.warn(
        `[Selector:${this.id}] Cannot set items - view not initialized`,
      );
      return;
    }
    // Update adapter
    Java.scheduleOnMainThread(() => {
      try {
        const ArrayAdapter = API.ArrayAdapter;
        const context = this.button.getContext();
        const R_layout = API.R_layout;
        const String = API.JString;
        // Convert JavaScript strings to Java strings
        const javaItems = items.map((item) => String.$new(item.lable));
        // const R = Java.use("android.R");

        const adapter = ArrayAdapter.$new(
          context,
          R_layout.simple_spinner_item.value,
          Java.array("java.lang.CharSequence", javaItems),
        );
        adapter.setDropDownViewResource(
          R_layout.simple_spinner_dropdown_item.value,
        );
        this.button.setAdapter(adapter);
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
