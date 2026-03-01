import { API } from "../api";
import { applyStyle } from "./style/style";
import { DarkNeonTheme } from "./style/theme";
import { UIComponent } from "./ui-components";

export class Text extends UIComponent {
  private content: string;

  constructor(id: string, content: string) {
    super(id);
    this.content = content;
    this.value = content;
  }

  protected createView(context: any): void {
    const TextView = API.TextView;
    const Html = API.Html;

    this.view = TextView.$new(context);
    applyStyle(this.view, "text", DarkNeonTheme);
    this.view.setText(Html.fromHtml(this.content));
  }

  protected updateView(): void {
    if (!this.view) return;
    Java.scheduleOnMainThread(() => {
      const Html = API.Html;
      this.view.setText(Html.fromHtml(this.value));
    });
  }

  public setText(content: string): void {
    this.content = content;
    this.value = content;
    this.updateView();
  }
}