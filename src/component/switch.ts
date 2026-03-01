import { API } from "../api";
import { applyStyle } from "./style/style";
import { DarkNeonTheme } from "./style/theme";
import { UIComponent } from "./ui-components";

export class Switch extends UIComponent {
  private label: string;
  private handler?: (vlaue: boolean) => void;

  private switchView: any;
  private labelView: any;

  private setOnValueChange(handler: (vlaue: boolean) => void) {
    this.handler = handler;
  }

  constructor(id: string, label: string, initialValue: boolean = false) {
    super(id);
    this.label = label;
    this.value = initialValue;
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const Gravity = API.Gravity;
    const TextView = API.TextView;
    const Switch = API.Switch;
    const String = API.JString;

    const row = LinearLayout.$new(context);
    row.setOrientation(LinearLayout.HORIZONTAL.value);
    row.setGravity(Gravity.CENTER_VERTICAL.value);
    applyStyle(row, "row", DarkNeonTheme);

    const label = TextView.$new(context);
    label.setText(String.$new(this.label));
    applyStyle(label, "text", DarkNeonTheme);
    label.setLayoutParams(
      LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1),
    );

    const sw = Switch.$new(context);
    sw.setChecked(this.value);
    sw.setText(String.$new("")); // 不用自带文字

    row.addView(label);
    row.addView(sw);

    this.view = row;
    this.switchView = sw;
    this.labelView = label;

    const Listener = API.CompoundButtonOnCheckedChangeListener;
    const self = this;

    const changeListener = Java.registerClass({
      name:
        "com.frida.MyCheckedChangeListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [Listener],
      methods: {
        onCheckedChanged: function (_btn: any, isChecked: boolean) {
          self.value = isChecked;
          self.emit("valueChanged", isChecked);
          if (self.handler) setImmediate(() => self.handler!(isChecked));
        },
      },
    });

    this.switchView.setOnCheckedChangeListener(changeListener.$new());
  }

  protected updateView(): void {
    if (!this.view) return;
    Java.scheduleOnMainThread(() => {
      if (this.switchView) this.switchView.setChecked(this.value);
    });
  }

  public setLabel(label: string): void {
    this.label = label;
    if (!this.view) return;
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      if (this.labelView) this.labelView.setText(String.$new(label));
    });
  }
}