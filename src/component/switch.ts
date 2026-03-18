import Java from "frida-java-bridge";
import { API } from "../api.js";
import { applyStyle, dp } from "./style/style.js";
import { UIComponent } from "./ui-components.js";

export class Switch extends UIComponent {
  private label: string;
  private handler?: (value: boolean) => void;

  private labelView: any;
  private switchView: any;

  public onValueChange(handler: (value: boolean) => void) {
    this.handler = handler;
  }

  constructor(
    id: string,
    label: string,
    initialValue: boolean = false,
    handler?: (value: boolean) => void,
  ) {
    super(id);
    this.label = label;
    this.value = initialValue;
    this.handler = handler;
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const Gravity = API.Gravity;
    const TextView = API.TextView;
    const Switch = API.Switch;
    const String = API.JString;
    const OnClickListener = API.OnClickListener;
    const OnCheckedChangeListener = API.OnCheckedChangeListener;

    const theme = this.menu.options.theme!;

    // 外层整行卡片
    const row = LinearLayout.$new(context);
    row.setOrientation(LinearLayout.HORIZONTAL.value);
    row.setGravity(Gravity.CENTER_VERTICAL.value);
    applyStyle(row, "row", theme);
    row.setPadding(dp(context, 14), dp(context, 12), dp(context, 14), dp(context, 12));

    // 左侧标题
    const label = TextView.$new(context);
    label.setText(String.$new(this.label));
    applyStyle(label, "text", theme);
    label.setTextSize(2, 14);
    try {
      label.setTypeface(null, 1);
    } catch (_e) {}
    label.setSingleLine(true);
    label.setGravity(Gravity.LEFT.value | Gravity.CENTER_VERTICAL.value);
    label.setLayoutParams(
      LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0),
    );

    // 右侧原生开关
    const sw = Switch.$new(context);
    sw.setText(String.$new(""));
    sw.setChecked(!!this.value);
    sw.setShowText(false);

    try {
      sw.setMinWidth(dp(context, 50));
      sw.setMinimumWidth(dp(context, 50));
    } catch (_e) {}

    try {
      sw.setSwitchMinWidth(dp(context, 50));
    } catch (_e) {}

    try {
      sw.setScaleX(1.05);
      sw.setScaleY(1.05);
    } catch (_e) {}

    const switchLp = LinearLayoutParams.$new(
      ViewGroupLayoutParams.WRAP_CONTENT.value,
      ViewGroupLayoutParams.WRAP_CONTENT.value,
    );
    switchLp.leftMargin = dp(context, 12);
    sw.setLayoutParams(switchLp);

    const self = this;

    const checkedListener = Java.registerClass({
      name:
        "com.frida.MyCheckedChangeListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnCheckedChangeListener],
      methods: {
        onCheckedChanged: function (_buttonView: any, isChecked: boolean) {
          self.value = !!isChecked;
          self.emit("valueChanged", self.value);
          if (self.handler) {
            setImmediate(() => self.handler!(self.value));
          }
        },
      },
    });

    sw.setOnCheckedChangeListener(checkedListener.$new());

    const clickListener = Java.registerClass({
      name:
        "com.frida.MySwitchRowClickListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnClickListener],
      methods: {
        onClick: function (_v: any) {
          if (!self.switchView) return;
          self.switchView.setChecked(!self.switchView.isChecked());
        },
      },
    });

    row.setClickable(true);
    row.setOnClickListener(clickListener.$new());

    row.addView(label);
    row.addView(sw);

    this.labelView = label;
    this.switchView = sw;
    this.view = row;
  }

  protected updateView(): void {
    if (!this.switchView) return;

    Java.scheduleOnMainThread(() => {
      this.switchView.setChecked(!!this.value);
    });
  }

  public setLabel(label: string): void {
    this.label = label;
    if (!this.labelView) return;

    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.labelView.setText(String.$new(label));
    });
  }
}