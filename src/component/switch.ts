import { API } from "../api";
import { UIComponent } from "./ui-components";

export class Switch extends UIComponent {
  private label: string;
  private handler?: (vlaue: boolean) => void;
  private setOnValueChange(handler: (vlaue: boolean) => void) {
    this.handler = handler;
  }

  constructor(id: string, label: string, initialValue: boolean = false) {
    super(id);
    this.label = label;
    this.value = initialValue;
  }

  protected createView(context: any): void {
    const Switch = API.Switch;
    const String = API.JString;
    const Color = API.Color;

    this.view = Switch.$new(context);
    this.view.setText(String.$new(this.label));
    this.view.setTextColor(Color.WHITE.value);
    this.view.setChecked(this.value);
    const CompoundButtonOnCheckedChangeListener =
      API.CompoundButtonOnCheckedChangeListener;
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
          if (self.handler) self.handler(isChecked);
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
      const String = API.JString
      this.view.setText(String.$new(label));
    });
  }
}
