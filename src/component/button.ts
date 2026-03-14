import { API } from "../api";
import { Logger } from "../logger";
import { applyStyle } from "./style/style";
import { UIComponent } from "./ui-components";

export class Button extends UIComponent {
  private label: string;
  private handler?: () => void;
  private kind: "primary" | "danger" = "primary";

  constructor(
    id: string,
    label: string,
    kind: "primary" | "danger" = "primary",
    handler?: () => void,
  ) {
    super(id);
    this.label = label;
    this.kind = kind;
    this.handler = handler;
    this.value = null;
  }

  protected createView(context: any): void {
    const Button = API.Button;
    const String = API.JString;
    const Gravity = API.Gravity;

    this.view = Button.$new(context);
    this.view.setText(String.$new(this.label));

    applyStyle(
      this.view,
      this.kind === "danger" ? "dangerButton" : "primaryButton",
      this.menu.options.theme!,
    );

    try {
      this.view.setGravity(Gravity.CENTER.value);
    } catch (_e) {}

    const OnClickListener = API.OnClickListener;
    const self = this;
    const clickListener = Java.registerClass({
      name:
        "com.frida.MyClickListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnClickListener],
      methods: {
        onClick: function (_v) {
          self.emit("click");
          if (self.handler) {
            setImmediate(self.handler);
          }
        },
      },
    });

    this.view.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    // Button value doesn't affect UI
  }

  public setLabel(label: string): void {
    this.label = label;
    if (!this.view) {
      Logger.instance.warn(
        `[Button:${this.id}] Cannot set label - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.view.setText(String.$new(label));
    });
  }

  public onClick(handler: () => void): void {
    this.handler = handler;
  }
}