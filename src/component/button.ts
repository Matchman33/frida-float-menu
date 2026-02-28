import { API } from "../api";
import { UIComponent } from "./ui-components";

export class Button extends UIComponent {
  private label: string;
  private onClick: (() => void) | null = null;

  constructor(id: string, label: string) {
    super(id);
    this.label = label;
    this.value = null; // Buttons don't have a value
  }

  protected createView(context: any): void {
    const Button = API.Button;
    this.button = Button.$new(context);
    const String = API.JString;
    const Color = API.Color;

    this.button.setText(String.$new(this.label));
    this.button.setTextColor(Color.WHITE.value);
    this.button.setBackgroundColor(0xff555555 | 0); // gray background
    this.button.setPadding(16, 8, 16, 8);

    const OnClickListener = API.OnClickListener;
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
            setImmediate(self.onClick);
          }
        },
      },
    });
    this.button.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    // Button value doesn't affect UI
  }

  /**
   * Set button label
   */
  public setLabel(label: string): void {
    this.label = label;
    if (!this.button) {
      console.warn(
        `[Button:${this.id}] Cannot set label - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.button.setText(String.$new(label));
    });
  }

  /**
   * Set click handler
   */
  public setOnClick(handler: () => void): void {
    this.onClick = handler;
  }
}
