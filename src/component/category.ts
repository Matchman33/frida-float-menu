import { API } from "../api";
import { applyStyle } from "./style/style";
import { DarkNeonTheme } from "./style/theme";
import { UIComponent } from "./ui-components";

export class Category extends UIComponent {
  private label: string;

  constructor(id: string, label: string) {
    super(id);
    this.label = label;
    this.value = label;
  }

  protected createView(context: any): void {
    const TextView = API.TextView;
    const String = API.JString;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;

    this.view = TextView.$new(context);
    this.view.setText(String.$new(this.label));

    applyStyle(this.view, "category", DarkNeonTheme);

    this.view.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
  }

  protected updateView(): void {
    if (!this.view) return;
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.view.setText(String.$new(this.value));
    });
  }

  public setLabel(label: string): void {
    this.label = label;
    this.value = label;
    this.updateView();
  }
}