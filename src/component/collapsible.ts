import { API } from "../api.js";
import { UIComponent } from "./ui-components.js";
import { applyStyle, dp } from "./style/style.js";
import { Logger } from "../logger.js";
import Java from "frida-java-bridge";

export class Collapsible extends UIComponent {
  private title: string;
  private expanded: boolean;
  private contentContainer: any; // LinearLayout for child components
  private arrowView: any; // TextView for arrow icon
  pendingChildren: UIComponent[] = [];

  constructor(id: string, title: string, expanded: boolean = false) {
    super(id);
    this.title = title;
    this.expanded = expanded;
    this.value = expanded; // store expanded state
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const TextView = API.TextView;
    const String = API.JString;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const LinearLayoutParams = API.LinearLayoutParams;
    const View = API.View;
    const Gravity = API.Gravity;

    const GradientDrawable = Java.use(
      "android.graphics.drawable.GradientDrawable",
    );

    const createRoundedCard = (
      bgColor: number,
      cornerDp: number,
      strokeColor: number,
      strokeDp: number,
    ) => {
      const drawable = GradientDrawable.$new();
      drawable.setShape(GradientDrawable.RECTANGLE.value);
      drawable.setColor(bgColor | 0);
      drawable.setCornerRadius(dp(context, cornerDp));
      drawable.setStroke(dp(context, strokeDp), strokeColor | 0);
      return drawable;
    };

    // ===== Main container (card) =====
    const container = LinearLayout.$new(context);
    container.setOrientation(LinearLayout.VERTICAL.value);
    container.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    const theme = this.menu.options.theme!;
    const borderColor = theme.colors.divider;
    const cardBg = theme.colors.rowBg ?? theme.colors.cardBg;

    container.setBackground(createRoundedCard(cardBg, 10, borderColor, 1));
    container.setPadding(0, 0, 0, 0);
    container.setElevation(dp(context, 2));

    // ===== Title row (row) =====
    const titleRow = LinearLayout.$new(context);
    titleRow.setOrientation(LinearLayout.HORIZONTAL.value);
    titleRow.setGravity(Gravity.CENTER_VERTICAL.value);
    titleRow.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    titleRow.setPadding(
      dp(context, 14),
      dp(context, 12),
      dp(context, 14),
      dp(context, 12),
    );
    titleRow.setMinimumHeight(dp(context, 48));

    // Arrow (TextView)
    const arrowText = this.expanded ? "⌃" : "›";
    const arrowTextView = TextView.$new(context);
    arrowTextView.setText(String.$new(arrowText));
    arrowTextView.setSingleLine(true);
    arrowTextView.setTextColor(theme.colors.subText);
    arrowTextView.setTextSize(2, 20);
    arrowTextView.setGravity(Gravity.CENTER.value);
    arrowTextView.setPadding(dp(context, 12), 0, 0, 0);

    this.arrowView = arrowTextView;

    // Title text
    const titleView = TextView.$new(context);
    titleView.setText(String.$new(this.title));
    titleView.setSingleLine(true);
    applyStyle(titleView, "text", this.menu.options.theme!);
    titleView.setTypeface(null, 1); // BOLD
    titleView.setTextSize(2, 16);
    titleView.setLayoutParams(
      LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0),
    );

    titleRow.addView(titleView);
    titleRow.addView(this.arrowView);

    const divider = View.$new(context);
    divider.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        dp(context, 1),
      ),
    );
    divider.setBackgroundColor(borderColor);

    if (!this.expanded) {
      divider.setVisibility(View.GONE.value);
    }

    // ===== Content container =====
    this.contentContainer = LinearLayout.$new(context);
    this.contentContainer.setOrientation(LinearLayout.VERTICAL.value);
    const lp = LinearLayoutParams.$new(
      ViewGroupLayoutParams.MATCH_PARENT.value,
      ViewGroupLayoutParams.WRAP_CONTENT.value,
    );
    // lp.setMargins(0, 0, 0, dp(context, 10));
    this.contentContainer.setLayoutParams(lp);

    this.contentContainer.setPadding(
      dp(context, 10),
      dp(context, 10),
      dp(context, 10),
      dp(context, 10),
    );

    if (this.expanded) {
      this.contentContainer.setVisibility(View.VISIBLE.value);
    } else {
      this.contentContainer.setVisibility(View.GONE.value);
    }

    container.addView(titleRow);
    container.addView(divider);
    container.addView(this.contentContainer);

    this.view = container;

    // ✅ 把 init 前添加的子组件补进来（照 float-menu 的 pending 思路）
    if (this.pendingChildren.length > 0) {
      const ctx = this.view.getContext();
      for (const c of this.pendingChildren) {
        try {
          this.menu.uiComponents.set(c.getId(), c);
          c.setMenu(this.menu);
          c.init(ctx);
          const v = this.menu.prepareComponentView(ctx, c);
          if (v) this.contentContainer.addView(v);
          this.menu.bindComponentEvents(c);
        } catch (e) {
          Logger.instance.error(
            `[Collapsible:${this.id}] addChild: ${c.getId()} - ${e}`,
          );
        }
      }
      this.pendingChildren = [];
    }

    // store references
    (this.view as any).titleRow = titleRow;
    (this.view as any).titleView = titleView;
    (this.view as any).contentContainer = this.contentContainer;
    (this.view as any).divider = divider;

    // ===== Click listener =====
    const OnClickListener = API.OnClickListener;
    const self = this;

    const clickListener = Java.registerClass({
      name:
        "com.frida.CollapsibleClickListener" +
        Date.now() +
        Math.random().toString(36).substring(4),
      implements: [OnClickListener],
      methods: {
        onClick: function () {
          self.toggle();
        },
      },
    });

    titleRow.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      Logger.instance.warn(
        `[Collapsible:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }

    this.expanded = this.value;

    Java.scheduleOnMainThread(() => {
      const View = API.View;
      const String = API.JString;

      const contentContainer = (this.view as any).contentContainer;
      const divider = (this.view as any).divider;

      if (contentContainer) {
        contentContainer.setVisibility(
          this.expanded ? View.VISIBLE.value : View.GONE.value,
        );
      }

      if (divider) {
        divider.setVisibility(
          this.expanded ? View.VISIBLE.value : View.GONE.value,
        );
      }

      if (this.arrowView) {
        const arrowText = this.expanded ? "⌃" : "›";
        this.arrowView.setText(String.$new(arrowText));
      }
    });
  }

  /** Toggle expanded/collapsed state */
  public toggle(): void {
    this.value = !this.value;
    this.updateView();
    this.emit("toggle", this.value);
  }

  /** Expand */
  public expand(): void {
    this.value = true;
    this.updateView();
    this.emit("expand");
  }

  /** Collapse */
  public collapse(): void {
    this.value = false;
    this.updateView();
    this.emit("collapse");
  }

  /** Set title */
  public setTitle(title: string): void {
    this.title = title;
    if (!this.view) {
      Logger.instance.warn(
        `[Collapsible:${this.id}] Cannot set title - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const titleView = (this.view as any).titleView;
      if (titleView) {
        const String = API.JString;
        titleView.setText(String.$new(title));
      }
    });
  }

  public addChild(component: UIComponent): void {
    // 还没 init / contentContainer 不存在 -> 先排队
    if (!this.contentContainer || !this.view) {
      this.pendingChildren.push(component);
      return;
    }

    Java.scheduleOnMainThread(() => {
      try {
        // 必须添加，不然无法通过id取得组件
        this.menu.uiComponents.set(component.getId(), component);
        component.setMenu(this.menu);

        const ctx = this.view.getContext(); // ✅ 跟 float-menu 一样，拿容器 context
        // component.init(ctx);
        // const v = component.getView();
        const v = this.menu.prepareComponentView(ctx, component);

        if (v) this.contentContainer.addView(v);

        this.menu.bindComponentEvents(component);
      } catch (e) {
        Logger.instance.error(`[Collapsible:${this.id}] addChild error: ${e}`);
      }
    });
  }

  public addChildren(components: UIComponent[]): void {
    for (const c of components) this.addChild(c);
  }
  /** Remove child view */
  public removeChildView(view: any): void {
    if (!this.contentContainer) return;
    Java.scheduleOnMainThread(() => {
      try {
        this.contentContainer.removeView(view);
      } catch (_e) {}
    });
  }

  /** Clear all children */
  public clearChildren(): void {
    if (!this.contentContainer) return;
    Java.scheduleOnMainThread(() => {
      this.contentContainer.removeAllViews();
    });
  }
}
