import { API } from "../api";
import { Logger } from "../logger";
import { applyStyle } from "./style/style";
import { UIComponent } from "./ui-components";

export class Selector extends UIComponent {
  private items: { lable: string; [key: string]: any }[];
  private selectedIndex: number;
  private handler?: (value: any) => {};
  private context: any;

  constructor(
    id: string,
    items: { lable: string; [key: string]: any }[],
    selectedIndex: number = 0,
    handler?: (value: any) => {},
  ) {
    super(id);
    this.items = items;
    this.selectedIndex = selectedIndex;
    this.value = items[selectedIndex];
    this.handler = handler;
  }

  public getValue(): { lable: string; [key: string]: any } {
    return this.value;
  }

  protected createView(context: any): void {
    this.context = context;
    const Spinner = API.Spinner;
    const ArrayAdapter = API.ArrayAdapter;
    const String = API.JString;
    this.view = Spinner.$new(context);
    this.view.setBackgroundColor(0xff555555 | 0); // gray background
    // applyStyle(this.view, 'inputTrigger', this.menu.options.theme!);

    const res = context.getResources();
    const itemLayout = res.getIdentifier(
      "simple_spinner_item",
      "layout",
      "android",
    );
    const dropLayout = res.getIdentifier(
      "simple_spinner_dropdown_item",
      "layout",
      "android",
    );
    // Convert JavaScript strings to Java strings
    const javaItems = this.items.map((item) => String.$new(item.lable));
    const adapter = ArrayAdapter.$new(
      context,
      itemLayout,
      Java.array("java.lang.String", javaItems),
    );
    adapter.setDropDownViewResource(dropLayout);
    this.view.setAdapter(adapter);
    this.view.setSelection(this.selectedIndex);

    // Try to set text color (may not work on all Android versions)
    try {
      this.view.setPopupBackgroundResource(0xff333333 | 0);
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
    this.view.setOnItemSelectedListener(itemSelectedListener.$new());
  }

  public onValueChange(handler: (value: any) => {}) {
    this.handler = handler;
  }

  protected updateView(): void {
    if (!this.view) {
      Logger.instance.warn(
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
        this.view.setSelection(index);
      });
    }
  }

  /**
   * Set selector items
   */
  public setItems(items: { lable: string; [key: string]: any }[]): void {
    this.items = items;
    if (!this.view) {
      Logger.instance.warn(
        `[Selector:${this.id}] Cannot set items - view not initialized`,
      );
      return;
    }
    // Update adapter
    Java.scheduleOnMainThread(() => {
      try {
        const ArrayAdapter = API.ArrayAdapter;
        const String = API.JString;
        // Convert JavaScript strings to Java strings
        const javaItems = items.map((item) => String.$new(item.lable));

        const res = this.context.getResources();
        const itemLayout = res.getIdentifier(
          "simple_spinner_item",
          "layout",
          "android",
        );
        const dropLayout = res.getIdentifier(
          "simple_spinner_dropdown_item",
          "layout",
          "android",
        );
        const adapter = ArrayAdapter.$new(
          this.context,
          itemLayout,
          Java.array("java.lang.CharSequence", javaItems),
        );
        adapter.setDropDownViewResource(
          dropLayout,
        );
        this.view.setAdapter(adapter);
      } catch (error) {
        Logger.instance.error(`[Selector:${this.id}] Failed to set items:`, error);
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
