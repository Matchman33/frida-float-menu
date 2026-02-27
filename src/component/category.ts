import { UIComponent } from "./ui-components";

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
