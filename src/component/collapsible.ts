import { API } from "../api";
import { UIComponent } from "./ui-components";
import { applyStyle, dp } from "./style/style";
import { DarkNeonTheme } from "./style/theme";

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

    // ===== Main container (card) =====
    const container = LinearLayout.$new(context);
    container.setOrientation(LinearLayout.VERTICAL.value);
    container.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    // ✅ 外层卡片风格
    applyStyle(container, "card", DarkNeonTheme);

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

    // ✅ 标题行用 row，融入整体
    applyStyle(titleRow, "row", DarkNeonTheme);

    // 标题行内边距微调（row 已有 padding，这里可按你口味微调）
    // titleRow.setPadding(
    //   dp(context, 12),
    //   dp(context, 10),
    //   dp(context, 12),
    //   dp(context, 10),
    // );

    // Arrow (TextView)
    const arrowText = this.expanded ? "▼" : "▶";
    const arrowTextView = TextView.$new(context);
    arrowTextView.setText(String.$new(arrowText));
    arrowTextView.setSingleLine(true);
    applyStyle(arrowTextView, "caption", DarkNeonTheme);
    arrowTextView.setPadding(0, 0, dp(context, 8), 0);

    this.arrowView = arrowTextView;

    // Title text
    const titleView = TextView.$new(context);
    titleView.setText(String.$new(this.title));
    titleView.setSingleLine(true);
    applyStyle(titleView, "text", DarkNeonTheme);
    titleView.setTypeface(null, 1); // BOLD
    titleView.setLayoutParams(
      LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0),
    );

    titleRow.addView(this.arrowView);
    titleRow.addView(titleView);

    // ===== Content container =====
    this.contentContainer = LinearLayout.$new(context);
    this.contentContainer.setOrientation(LinearLayout.VERTICAL.value);
    this.contentContainer.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    // ✅ 内容区缩进 + 间距（比你之前更像设置分组）
    this.contentContainer.setPadding(
      dp(context, 2),
      dp(context, 2),
      dp(context, 2),
      dp(context, 4),
    );

    if (this.expanded) {
      this.contentContainer.setVisibility(View.VISIBLE.value);
    } else {
      this.contentContainer.setVisibility(View.GONE.value);
    }

    container.addView(titleRow);
    container.addView(this.contentContainer);

    this.view = container;

    // ✅ 把 init 前添加的子组件补进来（照 float-menu 的 pending 思路）
    if (this.pendingChildren.length > 0) {
      const ctx = this.view.getContext();
      for (const c of this.pendingChildren) {
        try {
          c.init(ctx);
          const v = c.getView();
          if (v) this.contentContainer.addView(v);
        } catch (e) {}
      }
      this.pendingChildren = [];
    }

    // store references
    (this.view as any).titleRow = titleRow;
    (this.view as any).titleView = titleView;
    (this.view as any).contentContainer = this.contentContainer;

    // ===== Click listener =====
    const OnClickListener = API.OnClickListener;
    const self = this;

    const clickListener = Java.registerClass({
      name:
        "com.frida.CollapsibleClickListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
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
      console.warn(
        `[Collapsible:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }

    this.expanded = this.value;

    Java.scheduleOnMainThread(() => {
      const View = API.View;
      const String = API.JString;

      const contentContainer = (this.view as any).contentContainer;

      if (contentContainer) {
        contentContainer.setVisibility(
          this.expanded ? View.VISIBLE.value : View.GONE.value,
        );
      }

      if (this.arrowView) {
        const arrowText = this.expanded ? "▼" : "▶";
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
      console.warn(
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
        const ctx = this.view.getContext(); // ✅ 跟 float-menu 一样，拿容器 context
        component.init(ctx);
        const v = component.getView();
        if (v) this.contentContainer.addView(v);
      } catch (e) {}
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
