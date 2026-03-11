import { API } from "../../api";
import { EventEmitter } from "../../event-emitter";
import { Logger } from "../../logger";
import { dp } from "../style/style";
import { Theme } from "../style/theme";
interface TabDefinition {
  id: string;
  label: string;
}

export class TabsView {
  private context: any;
  private parentView: any;
  private theme: any;
  tabContainer: any;
  // Tab management
  public tabs: Map<
    string,
    {
      label: string;
      container: any; // ✅ 内容 LinearLayout（你 addView 用它）
      root?: any; // ✅ 这个 tab 的根视图（建议就是 ScrollView）
      scrollView?: any; // ✅ 这个 tab 自己的 ScrollView
      components: Set<string>;
    }
  > = new Map();
  activeTabId: any;
  tabView: any;
  menuPanelView: any;
  logger: Logger = Logger.instance;
  initTabs: TabDefinition[];
  public currentContentContainer: any;
  currentScrollView: any;
  private eventEmitter: EventEmitter = new EventEmitter();

  constructor(
    context: any,
    theme: Theme,
    initTabs: TabDefinition[],
    activeTabId?: string,
  ) {
    this.context = context;
    this.theme = theme;
    this.initTabs = initTabs;
    this.activeTabId = activeTabId;
  }

  public createTabView(parentView: any) {
    this.parentView = parentView;
    if (this.tabs.size === 1 && this.tabs.has("default")) {
      return;
    }
    try {
      const LinearLayout = API.LinearLayout;
      const LinearLayoutParams = API.LinearLayoutParams;
      const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
      const TextView = API.TextView;
      const OnClickListener = API.OnClickListener;
      const JString = API.JString;
      const HorizontalScrollView = API.HorizontalScrollView;
      const GradientDrawable = API.GradientDrawable;
      const Gravity = API.Gravity;

      const self = this;

      // ===== outer scroll view =====
      const scrollView = HorizontalScrollView.$new(this.context);
      scrollView.setHorizontalScrollBarEnabled(false);
      scrollView.setScrollbarFadingEnabled(true);
      scrollView.setFillViewport(true); // ✅ 让内容不足时也铺满，视觉更稳定

      const scrollLp = LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      );
      scrollView.setLayoutParams(scrollLp);

      // ✅ 胶囊条背景（暗底 + 圆角 + 描边）
      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(this.context, 14));
      bg.setColor(this.theme.colors.cardBg);
      bg.setStroke(dp(this.context, 1), this.theme.colors.divider);
      scrollView.setBackgroundDrawable(bg);

      // 内边距（让 tab 不贴边）
      scrollView.setPadding(
        dp(this.context, 8),
        dp(this.context, 6),
        dp(this.context, 8),
        dp(this.context, 6),
      );

      // ===== inner container (tabs) =====
      const tabContainer = LinearLayout.$new(this.context);
      tabContainer.setOrientation(0); // HORIZONTAL
      tabContainer.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );

      // 存引用，切换 tab 时更新样式
      this.tabContainer = tabContainer;

      // ===== helper: style tab item =====
      const styleTab = (tv: any, active: boolean) => {
        // 统一字体/对齐/内边距
        tv.setAllCaps(false);
        tv.setSingleLine(true);
        tv.setGravity(Gravity.CENTER.value);
        tv.setTextSize(2, this.theme.textSp.body);
        tv.setPadding(
          dp(this.context, 12),
          dp(this.context, 8),
          dp(this.context, 12),
          dp(this.context, 8),
        );

        // 背景：active -> 实心 accent；inactive -> 透明
        const d = GradientDrawable.$new();
        d.setCornerRadius(dp(this.context, 12));
        if (active) {
          d.setColor(this.theme.colors.accent);
          tv.setTextColor(0xffffffff | 0);
        } else {
          d.setColor(0x00000000);
          tv.setTextColor(this.theme.colors.subText);
          // 给未选中一个轻描边（可选，想更干净就删掉这行）
          d.setStroke(dp(this.context, 1), this.theme.colors.divider);
        }
        tv.setBackgroundDrawable(d);

        // 选中更醒目一点
        try {
          tv.setTypeface(null, active ? 1 : 0);
        } catch (e) {}
      };

      // ===== create each tab =====
      for (const [tabId, tabInfo] of this.tabs) {
        const tabText = TextView.$new(this.context);
        tabText.setText(JString.$new(tabInfo.label));

        // layout params：紧凑间距
        const btnLp = LinearLayoutParams.$new(
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        );
        btnLp.setMargins(
          dp(this.context, 6),
          dp(this.context, 2),
          dp(this.context, 6),
          dp(this.context, 2),
        );
        tabText.setLayoutParams(btnLp);

        // 初始样式
        styleTab(tabText, tabId === this.activeTabId);

        // 点击切换
        const tabClickListener = Java.registerClass({
          name:
            "com.example.TabClickListener" +
            Date.now() +
            Math.random().toString(36).substring(6) +
            "_" +
            tabId,
          implements: [OnClickListener],
          methods: {
            onClick: function () {
              self.switchTab(tabId);
            },
          },
        });

        tabText.setOnClickListener(tabClickListener.$new());
        tabContainer.addView(tabText);
      }

      // ✅ 把 tabs 放进 scrollView
      scrollView.addView(tabContainer);

      // ✅ 对外暴露
      this.tabView = scrollView;

      parentView.addView(this.tabView);
    } catch (error) {
      this.logger.error("Failed to create tab view: " + error);
    }
  }
  private switchTab(tabId: string): void {
    if (!this.tabs.has(tabId) || tabId === this.activeTabId) return;

    const oldTabId = this.activeTabId;
    this.activeTabId = tabId;
    this.refreshTabsUI();

    Java.scheduleOnMainThread(() => {
      try {
        const View = API.View;

        for (const [id, tabInfo] of this.tabs) {
          const root = tabInfo.root; // ✅ 每个 tab 的 ScrollView
          if (!root) continue;

          if (id === tabId) {
            root.setVisibility(View.VISIBLE.value);
            this.currentContentContainer = tabInfo.container; // ✅ LinearLayout
            this.currentScrollView = tabInfo.scrollView; // ✅ 当前 tab 的 ScrollView
          } else {
            root.setVisibility(View.GONE.value);
          }
        }

        if (this.tabContainer) {
          const tabIds = Array.from(this.tabs.keys());
          const childCount = this.tabContainer.getChildCount();
          for (let i = 0; i < childCount && i < tabIds.length; i++) {
            const tv = Java.cast(this.tabContainer.getChildAt(i), API.TextView);
            this.updateTabStyle(tv, tabIds[i] === tabId);
          }
        }

        this.eventEmitter.emit("tabChanged", tabId, oldTabId);
      } catch (error) {
        Logger.instance.error(`Failed to switch to tab ${tabId}:`, error);
      }
    });
  }
  private updateTabStyle(button: any, isActive: boolean) {
    const GradientDrawable = API.GradientDrawable;

    // dp helper（如果当前文件里没有 dp(context, x)，用你已有的那个）
    const ctx = button.getContext();

    const radius = dp(ctx, 12); // 胶囊圆角
    const strokeW = dp(ctx, 1);
    const padH = dp(ctx, 12);
    const padV = dp(ctx, 8);

    // 基础字体/内边距（避免每处都散落 setTextSize）
    try {
      button.setAllCaps(false);
    } catch (e) {}
    button.setSingleLine(true);
    button.setTextSize(2, this.theme!.textSp.body);
    button.setPadding(padH, padV, padH, padV);

    // 背景
    const drawable = GradientDrawable.$new();
    drawable.setCornerRadius(radius);

    if (isActive) {
      // ✅ 激活：accent 实心 + 白字
      drawable.setColor(this.theme!.colors.accent);
      button.setTextColor(0xffffffff | 0);
      try {
        button.setTypeface(null, 1); // bold
      } catch (e) {}
    } else {
      // ✅ 未激活：透明底 + divider 描边 + 次级文字色
      drawable.setColor(0x00000000);
      drawable.setStroke(strokeW, this.theme!.colors.divider);
      button.setTextColor(this.theme!.colors.subText);
      try {
        button.setTypeface(null, 0);
      } catch (e) {}
    }

    button.setBackgroundDrawable(drawable);
  }
  private refreshTabsUI(): void {
    try {
      if (!this.tabContainer) return;

      const GradientDrawable = API.GradientDrawable;
      const count = this.tabContainer.getChildCount();

      // tabs 的遍历顺序和 child 顺序一致
      const tabIds = Array.from(this.tabs.keys());

      for (let i = 0; i < count; i++) {
        const tv = this.tabContainer.getChildAt(i);
        const tabId = tabIds[i];
        const active = tabId === this.activeTabId;

        const d = GradientDrawable.$new();
        d.setCornerRadius(dp(this.context, 12));
        if (active) {
          d.setColor(this.theme!.colors.accent);
          tv.setTextColor(0xffffffff | 0);
          try {
            tv.setTypeface(null, 1);
          } catch (e) {}
        } else {
          d.setColor(0x00000000);
          d.setStroke(dp(this.context, 1), this.theme!.colors.divider);
          tv.setTextColor(this.theme!.colors.subText);
          try {
            tv.setTypeface(null, 0);
          } catch (e) {}
        }
        tv.setBackgroundDrawable(d);
      }
    } catch (e) {}
  }

  /**
   * Initialize tabs from options
   */
  public initializeTabs(): void {
    // Clear existing tabs
    this.tabs.clear();

    // Determine if we should show tabs
    if (this.initTabs && this.initTabs.length > 0) {
      // Create tab entries
      for (const tabDef of this.initTabs) {
        this.tabs.set(tabDef.id, {
          label: tabDef.label,
          container: null, // Will be created in show()
          components: new Set<string>(),
        });
      }

      // Set active tab
      if (this.activeTabId && this.tabs.has(this.activeTabId)) {
        this.activeTabId = this.activeTabId;
      } else if (this.initTabs.length > 0) {
        this.activeTabId = this.initTabs[0].id;
      }
    } else {
      // No tabs defined, create default tab
      this.tabs.set("default", {
        label: "Default",
        container: null,
        components: new Set<string>(),
      });
      this.activeTabId = "default";
    }
  }
  /**
   * 为每个 tab 创建一个 ScrollView 作为容器
   */
  public createTabContainer(): void {
    const ScrollView = API.ScrollView;
    const LinearLayout = API.LinearLayout;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const LinearLayoutParams = API.LinearLayoutParams;
    const View = API.View;

    // ✅ wrapper：叠放每个 tab 的 root（每个 tab 一个 ScrollView）
    const tabRootsWrapper = LinearLayout.$new(this.context);
    tabRootsWrapper.setOrientation(LinearLayout.VERTICAL.value);
    tabRootsWrapper.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    if (!this.tabs || this.tabs.size === 0) {
      Logger.instance.warn("[FloatMenu] tabs is empty, tab container will be blank.");
    }

    let firstTabId: string | null = null;
    let firstTabInfo: any = null;
    for (const [tabId, tabInfo] of this.tabs) {
      if (!firstTabId) {
        firstTabId = tabId;
        firstTabInfo = tabInfo;
      }

      // ✅ 每个 tab 自己的 ScrollView
      const sv = ScrollView.$new(this.context);
      sv.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          0,
          1.0,
        ),
      );

      try {
        sv.setBackgroundColor(0x00000000);
      } catch (e) {}
      try {
        sv.setFillViewport(true);
        sv.setVerticalScrollBarEnabled(false);
      } catch (e) {}

      // ✅ 内容容器：LinearLayout（你 add row/card 都往这里加）
      const tabContainer = LinearLayout.$new(this.context);
      tabContainer.setOrientation(LinearLayout.VERTICAL.value);
      tabContainer.setLayoutParams(
        ViewGroupLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );

      // ✅ padding 建议放内容容器上（避免 wrapper padding 叠加）
      tabContainer.setPadding(
        dp(this.context, 10),
        dp(this.context, 10),
        dp(this.context, 10),
        dp(this.context, 10),
      );
      tabContainer.setPadding(0, 0, 0, dp(this.context, 4)); // 你想保留底部间距就留
      sv.addView(tabContainer);

      // ✅ 显隐：切换的是 sv
      if (tabId === this.activeTabId) {
        sv.setVisibility(View.VISIBLE.value);
        this.currentContentContainer = tabContainer;
        this.currentScrollView = sv; // ✅ 当前活跃 tab 的滚动容器
      } else {
        sv.setVisibility(View.GONE.value);
      }

      // ✅ 写回 tabInfo（关键：保持 container = 内容容器）
      tabInfo.container = tabContainer;
      tabInfo.scrollView = sv;
      tabInfo.root = sv;

      tabRootsWrapper.addView(sv);
    }
    // ✅ activeTabId 没命中 -> 默认第一个
    if (
      (!this.currentContentContainer || !this.currentScrollView) &&
      firstTabId &&
      firstTabInfo
    ) {
      this.activeTabId = firstTabId;

      if (firstTabInfo.root)
        firstTabInfo.root.setVisibility(View.VISIBLE.value);
      this.currentContentContainer = firstTabInfo.container;
      this.currentScrollView = firstTabInfo.scrollView;
    }



    this.parentView.addView(tabRootsWrapper);
  }
}
