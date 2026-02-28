import { API } from "../api";
import { UIComponent } from "./ui-components";

export class Category extends UIComponent {
  private label: string;

  constructor(id: string, label: string) {
    super(id);
    this.label = label;
    this.value = label; // Use value to store label
  }

  protected createView(context: any): void {
    const TextView = API.TextView
    const Color = API.Color
    const String = API.JString
    const LinearLayoutParams = API.LinearLayoutParams
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams

    this.button = TextView.$new(context);
    this.button.setText(String.$new(this.label));
    this.button.setTextColor(Color.WHITE.value);
    this.button.setTextSize(16);
    this.button.setTypeface(null, 1); // BOLD
    this.button.setBackgroundColor(0xff555555 | 0); // Medium gray background
    this.button.setPadding(16, 12, 16, 12);
    this.button.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
  }

  protected updateView(): void {
    if (!this.button) {
      console.warn(
        `[Category:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString
      this.button.setText(String.$new(this.value));
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
