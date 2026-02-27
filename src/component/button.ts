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
