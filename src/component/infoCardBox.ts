import Java from "frida-java-bridge";
import { API } from "../api.js";
import { applyStyle } from "./style/style.js";
import { UIComponent } from "./ui-components.js";

export class InfoCardText extends UIComponent {
  private content: string;
  private kind: "normal" | "note";
  private textView: any;
  private containerView: any;
  private size?: number;

  constructor(
    id: string,
    content: string,
    kind: "normal" | "note" = "normal",
    size?: number,
  ) {
    super(id);
    this.content = content;
    this.kind = kind;
    this.size = size;
    this.value = content;
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const TextView = API.TextView;
    const Html = API.Html;
    const Gravity = API.Gravity;

    const root = LinearLayout.$new(context);
    root.setOrientation(LinearLayout.VERTICAL.value);

    const rootLp = LinearLayoutParams.$new(
      ViewGroupLayoutParams.MATCH_PARENT.value,
      ViewGroupLayoutParams.WRAP_CONTENT.value,
    );
    rootLp.setMargins(0, 0, 0, dp(context, 12));
    root.setLayoutParams(rootLp);

    applyStyle(
      root,
      this.kind === "note" ? "noteCard" : "infoCard",
      this.menu.options.theme!,
    );

    const tv = TextView.$new(context);
    tv.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    applyStyle(
      tv,
      this.kind === "note" ? "noteText" : "text",
      this.menu.options.theme!,
    );

    if (this.size != null) {
      tv.setTextSize(2, this.size);
    }

    tv.setGravity(Gravity.LEFT.value);
    tv.setText(Html.fromHtml(this.content));

    root.addView(tv);

    this.textView = tv;
    this.containerView = root;
    this.view = root;
  }

  protected updateView(): void {
    if (!this.textView) return;

    Java.scheduleOnMainThread(() => {
      const Html = API.Html;
      this.textView.setText(Html.fromHtml(this.content));
    });
  }

  public setText(content: string): void {
    this.content = content;
    this.value = content;
    this.updateView();
  }

  public setKind(kind: "normal" | "note"): void {
    this.kind = kind;

    if (!this.containerView || !this.textView) return;

    Java.scheduleOnMainThread(() => {
      applyStyle(
        this.containerView,
        this.kind === "note" ? "noteCard" : "infoCard",
        this.menu.options.theme!,
      );

      applyStyle(
        this.textView,
        this.kind === "note" ? "noteText" : "text",
        this.menu.options.theme!,
      );

      if (this.size != null) {
        this.textView.setTextSize(2, this.size);
      }
    });
  }
}

function dp(context: any, v: number): number {
  const dm = context.getResources().getDisplayMetrics();
  return Math.floor(v * dm.density.value + 0.5);
}