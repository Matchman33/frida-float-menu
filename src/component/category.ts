import Java from "frida-java-bridge";
import { API } from "../api.js";
import { applyStyle, dp } from "./style/style.js";
import { UIComponent } from "./ui-components.js";

export class Category extends UIComponent {
  private label: string;
  private labelView: any;

  constructor(id: string, label: string) {
    super(id);
    this.label = label;
    this.value = label;
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const TextView = API.TextView;
    const View = API.View;
    const Gravity = API.Gravity;
    const String = API.JString;

    const theme = this.menu.options.theme!;

    const root = LinearLayout.$new(context);
    root.setOrientation(LinearLayout.HORIZONTAL.value);
    root.setGravity(Gravity.CENTER_VERTICAL.value);

    root.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    root.setPadding(dp(context, 2), dp(context, 10), dp(context, 2), dp(context, 8));

    const indicator = View.$new(context);
    const indicatorLp = LinearLayoutParams.$new(dp(context, 3), dp(context, 14));
    indicatorLp.setMargins(0, 0, dp(context, 10), 0);
    indicator.setLayoutParams(indicatorLp);

    const GradientDrawable = API.GradientDrawable
    const indicatorBg = GradientDrawable.$new();
    indicatorBg.setColor(theme.colors.accent | 0);
    indicatorBg.setCornerRadius(dp(context, 2));
    indicator.setBackground(indicatorBg);

    const labelView = TextView.$new(context);
    labelView.setText(String.$new(this.label));
    applyStyle(labelView, "category", theme);

    const textLp = LinearLayoutParams.$new(
      0,
      ViewGroupLayoutParams.WRAP_CONTENT.value,
      1.0,
    );
    labelView.setLayoutParams(textLp);

    root.addView(indicator);
    root.addView(labelView);

    this.labelView = labelView;
    this.view = root;
  }

  protected updateView(): void {
    if (!this.labelView) return;
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.labelView.setText(String.$new(this.value));
    });
  }

  public setLabel(label: string): void {
    this.label = label;
    this.value = label;
    this.updateView();
  }
}