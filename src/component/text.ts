import { API } from "../api";
import { applyStyle } from "./style/style";
import { UIComponent } from "./ui-components";

export class TextView extends UIComponent {
  private size: number;

  constructor(id: string, content: string, size: number = 16) {
    super(id);
    this.value = content;
    this.size = size;
  }

  protected createView(context: any): void {
    const TextView = API.TextView;
    const Html = API.Html;

    this.view = TextView.$new(context);
    applyStyle(this.view, "text", this.menu.options.theme!);
    this.view.setTextSize(this.size);

    this.view.setText(Html.fromHtml(this.value));
  }

  protected updateView(): void {
    if (!this.view) return;
    Java.scheduleOnMainThread(() => {
      const Html = API.Html;
      this.view.setText(Html.fromHtml(this.value));
    });
  }

  public setText(content: string): void {
    this.value = content;
    this.updateView();
  }

}