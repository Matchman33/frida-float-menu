import { API } from "../api";
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
    const Color = API.Color;
    const Html = API.Html;

    this.view = TextView.$new(context);
    this.view.setTextColor(Color.WHITE.value);
    this.view.setTextSize(14);
    // const String = Java.use("java.lang.String");
    // this.view.setText(String.$new(this.content));
    this.view.setText(Html.fromHtml(this.content));
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Text:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const Html = API.Html
      this.view.setText(Html.fromHtml(this.value));
    });
  }

  /**
   * Set text content
   */
  public setText(content: string): void {
    this.content = content;
    this.value = content;
    this.updateView();
  }
}
