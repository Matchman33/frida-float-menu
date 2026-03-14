import { API } from "../api";
import { applyStyle } from "./style/style";
import { UIComponent } from "./ui-components";

export class TextView extends UIComponent {
  private size?: number;
  private kind: "normal" | "note";

  constructor(
    id: string,
    content: string,
    kind: "normal" | "note" = "normal",
    size?: number,
  ) {
    super(id);
    this.value = content;
    this.kind = kind;
    this.size = size;
  }

  protected createView(context: any): void {
    const TextView = API.TextView;
    const Html = API.Html;
    const Gravity = API.Gravity;

    this.view = TextView.$new(context);

    applyStyle(
      this.view,
      this.kind === "note" ? "noteText" : "text",
      this.menu.options.theme!,
    );

    if (this.size != null) {
      this.view.setTextSize(2, this.size);
    }

    this.view.setGravity(Gravity.LEFT.value);
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