import Java from "frida-java-bridge";
import { API } from "../../api.js";
import { EventEmitter } from "../../event-emitter.js";
import { Logger } from "../../logger.js";
import { dp } from "../style/style.js";
import { Theme } from "../style/theme.js";
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
  tabScrollView: any;
  tabIndicatorView: any;
  private tabItemMap: Map<string, any> = new Map();

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
    this.tabItemMap.clear();
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
      const outerScroll = HorizontalScrollView.$new(this.context);
      outerScroll.setHorizontalScrollBarEnabled(false);
      outerScroll.setFillViewport(false); // ✅ 不要把内容拉伸到满宽（保持 WRAP_CONTENT 便于滚动）
      outerScroll.setPadding(
        dp(this.context, 12),
        dp(this.context, 6),
        dp(this.context, 12),
        dp(this.context, 6),
      );

      const scrollLp = LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      );
      // 在 scrollLp 创建后加：
      scrollLp.setMargins(0, 0, 0, 0);
      outerScroll.setLayoutParams(scrollLp);
      try {
        outerScroll.setClipToPadding(false);
      } catch {}
      try {
        outerScroll.setClipChildren(false);
      } catch {}

      // ✅ 胶囊条背景（暗底 + 圆角 + 描边）
      // const bg = GradientDrawable.$new();
      // bg.setCornerRadius(dp(this.context, 14));
      // bg.setColor(this.theme.colors.cardBg);
      // bg.setStroke(dp(this.context, 1), this.theme.colors.divider);
      // outerScroll.setBackgroundDrawable(bg);

      // 内边距（让 tab 不贴边）
      // outerScroll.setPadding(
      //   dp(this.context, 8),
      //   dp(this.context, 6),
      //   dp(this.context, 8),
      //   dp(this.context, 6),
      // );

      // ===== inner container (tabs) =====
      const tabContainer = LinearLayout.$new(this.context);
      tabContainer.setOrientation(0); // HORIZONTAL
      tabContainer.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );
      tabContainer.setPadding(0, 0, 0, 0);
      // 存引用，切换 tab 时更新样式
      // this.tabContainer = tabContainer;
      // outerScroll.addView(tabContainer);
      // this.tabView = outerScroll;
      this.tabContainer = tabContainer;
      outerScroll.addView(tabContainer);

      // ===== tab bar root (VERTICAL): scroll + indicator =====
      const tabBarRoot = LinearLayout.$new(this.context);
      tabBarRoot.setOrientation(1); // VERTICAL
      tabBarRoot.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );

      // 记录 scroll 引用（后面 switchTab 需要滚动）
      this.tabScrollView = outerScroll;

      // ===== indicator =====
      const indicator = API.View.$new(this.context);
      const indicatorLp = LinearLayoutParams.$new(
        dp(this.context, 0), // 初始宽度 0，第一次切换再算
        dp(this.context, 2), // 高度 2dp
      );
      indicatorLp.setMargins(
        dp(this.context, 12),
        dp(this.context, 2),
        dp(this.context, 12),
        dp(this.context, 0),
      );
      indicator.setLayoutParams(indicatorLp);
      // indicator.setBackgroundColor(this.theme.colors.accent); // 先用 accent（后面可换更亮）
      indicator.setBackgroundColor(0xffffffff | 0);
      this.tabIndicatorView = indicator;

      // assemble
      tabBarRoot.addView(outerScroll);
      tabBarRoot.addView(indicator);

      // 以后用 tabBarRoot 作为 tabView
      this.tabView = tabBarRoot;


      // ===== create each tab =====
      for (const [tabId, tabInfo] of this.tabs) {
        // tab item root
        const tabItem = LinearLayout.$new(this.context);
        tabItem.setOrientation(1); // VERTICAL
        tabItem.setGravity(Gravity.CENTER.value);

        // ✅ 不要任何背景（避免“点了变色”）
        try {
          tabItem.setBackground(null);
        } catch {}
        try {
          tabItem.setBackgroundColor(0x00000000);
        } catch {}

        // ✅ padding 决定 tab 的“大小”，不是 tab 之间的间距
        tabItem.setPadding(
          dp(this.context, 12),
          dp(this.context, 6),
          dp(this.context, 12),
          dp(this.context, 0),
        );

        // ✅ 可选：保存引用，刷新更快更稳（推荐）
        this.tabItemMap.set(tabId, tabItem);

        // layout params：不加边距，想更紧就全 0
        const itemLp = LinearLayoutParams.$new(
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        );
        itemLp.setMargins(0, 0, 0, 0);
        tabItem.setLayoutParams(itemLp);

        // label
        const label = TextView.$new(this.context);
        label.setText(JString.$new(tabInfo.label));
        label.setSingleLine(true);
        label.setAllCaps(false);
        label.setTextSize(2, this.theme.textSp.body);
        label.setGravity(Gravity.CENTER.value);

        // ✅ 不要背景
        try {
          label.setBackground(null);
        } catch {
          try {
            label.setBackgroundColor(0x00000000);
          } catch {}
        }

        // underline (蓝条)
        const underline = API.View.$new(this.context);
        const ulLp = LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          dp(this.context, 2),
        );
        ulLp.setMargins(0, dp(this.context, 6), 0, 0);
        underline.setLayoutParams(ulLp);
        underline.setBackgroundColor(this.theme.colors.accent); // ✅ 蓝条
        // 默认先隐藏，active 再显示
        underline.setVisibility(API.View.GONE.value);

        tabItem.addView(label);
        tabItem.addView(underline);

        // 初始样式（只改字体色 + 蓝条显示）
        this.updateTabStyle(tabItem, tabId === this.activeTabId);

        // 点击切换：监听挂在 tabItem 上（点击区域更大）
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

        tabItem.setOnClickListener(tabClickListener.$new());
        tabContainer.addView(tabItem);
      }
      // this.tabView = outerScroll;
      parentView.addView(this.tabView);
      // Java.scheduleOnMainThread(() =>
      //   this.updateTabIndicator(this.activeTabId),
      // );
    } catch (error) {
      this.logger.error("Failed to create tab view: " + error);
    }
  }

  private switchTab(tabId: string): void {
    if (!this.tabs.has(tabId) || tabId === this.activeTabId) return;

    const oldTabId = this.activeTabId;
    this.activeTabId = tabId;
    Java.scheduleOnMainThread(() => {
      try {
        const View = API.View;

        for (const [id, tabInfo] of this.tabs) {
          const root = tabInfo.root;
          if (!root) continue;

          if (id === tabId) {
            root.setVisibility(View.VISIBLE.value);
            this.currentContentContainer = tabInfo.container;
            this.currentScrollView = tabInfo.scrollView;
          } else {
            root.setVisibility(View.GONE.value);
          }
        }

        // ✅ 关键：UI 线程里刷新 tab 样式（underline/文字颜色）
        this.refreshTabsUI();

        // ✅ 如果你还保留全局 indicator，就在 UI 线程里更新
        // if (this.updateTabIndicator) this.updateTabIndicator(tabId);

        this.eventEmitter.emit("tabChanged", tabId, oldTabId);
      } catch (error) {
        Logger.instance.error(`Failed to switch to tab ${tabId}:`, error);
      }
    });
  }
  private updateTabStyle(tabItem: any, isActive: boolean) {
    try {
      const View = API.View;
      const TextView = API.TextView;

      const label = Java.cast(tabItem.getChildAt(0), TextView);
      const underline = tabItem.getChildAt(1);

      // ✅ 只做状态差异更新：文字颜色 + 蓝条显隐
      if (isActive) {
        label.setTextColor(this.theme!.colors.text);
        try {
          label.setTypeface(null, 1);
        } catch {}
        underline.setVisibility(View.VISIBLE.value);
      } else {
        label.setTextColor(this.theme!.colors.subText);
        try {
          label.setTypeface(null, 0);
        } catch {}
        underline.setVisibility(View.GONE.value);
      }
    } catch (e) {
      Logger.instance.error(e);
    }
  }

  private updateTabIndicator(activeTabId: string): void {
    try {
      if (!this.tabContainer || !this.tabIndicatorView || !this.tabScrollView)
        return;

      const tabIds = Array.from(this.tabs.keys());
      const idx = tabIds.indexOf(activeTabId);
      if (idx < 0) return;

      const child = this.tabContainer.getChildAt(idx);
      if (!child) return;

      const indicator = this.tabIndicatorView;
      const scroll = this.tabScrollView;

      // ✅ 一定要等布局完成后再算 left/width
      scroll.post(
        Java.registerClass({
          name:
            "TabIndicatorPost_" +
            Date.now() +
            Math.random().toString(36).slice(2),
          implements: [Java.use("java.lang.Runnable")],
          methods: {
            run: () => {
              try {
                const width = child.getWidth();
                const leftInContainer = child.getLeft();

                const scrollX = scroll.getScrollX();
                const padL = scroll.getPaddingLeft();

                const lp = indicator.getLayoutParams();
                lp.width = width;
                lp.leftMargin = padL + leftInContainer - scrollX;
                indicator.setLayoutParams(lp);
              } catch {}
            },
          },
        }).$new(),
      );
    } catch (e) {}
  }
  // private updateTabIndicator(activeTabId: string): void {
  //   try {
  //     if (!this.tabContainer || !this.tabIndicatorView) return;

  //     const tabIds = Array.from(this.tabs.keys());
  //     const idx = tabIds.indexOf(activeTabId);
  //     if (idx < 0) return;

  //     const child = this.tabContainer.getChildAt(idx);
  //     if (!child) return;

  //     // 指示线宽度 = tab 按钮宽度；位置 = tab 按钮 left
  //     const left = child.getLeft();
  //     const width = child.getWidth();

  //     const lp = this.tabIndicatorView.getLayoutParams();
  //     lp.width = width;

  //     // LinearLayoutParams 才有 setMargins（保险写法：直接写 leftMargin）
  //     try {
  //       lp.leftMargin = left + dp(this.context, 12); // +indicator 原本左右 margin
  //     } catch {}

  //     this.tabIndicatorView.setLayoutParams(lp);

  //     // // 让选中 tab 滚到可见（偏左一点即可）
  //     // if (this.tabScrollView) {
  //     //   const scroll = this.tabScrollView;
  //     //   scroll.post(
  //     //     Java.registerClass({
  //     //       name:
  //     //         "TabScrollTo_" + Date.now() + Math.random().toString(36).slice(2),
  //     //       implements: [Java.use("java.lang.Runnable")],
  //     //       methods: {
  //     //         run: () => {
  //     //           try {
  //     //             scroll.smoothScrollTo(
  //     //               Math.max(0, left - dp(this.context, 24)),
  //     //               0,
  //     //             );
  //     //           } catch {}
  //     //         },
  //     //       },
  //     //     }).$new(),
  //     //   );
  //     // }
  //   } catch (e) {}
  // }
  // private refreshTabsUI(): void {
  //   try {
  //     if (!this.tabContainer) return;

  //     const GradientDrawable = API.GradientDrawable;
  //     const count = this.tabContainer.getChildCount();

  //     // tabs 的遍历顺序和 child 顺序一致
  //     const tabIds = Array.from(this.tabs.keys());

  //     for (let i = 0; i < count; i++) {
  //       const tv = this.tabContainer.getChildAt(i);
  //       const tabId = tabIds[i];
  //       // const active = tabId === this.activeTabId;
  //       this.updateTabStyle(tv, tabId === this.activeTabId);
  //       // const d = GradientDrawable.$new();
  //       // d.setCornerRadius(dp(this.context, 8)); // ✅ 小圆角：像卡片标签，不是胶囊按钮

  //       // if (active) {
  //       //   // ✅ 选中：卡片底 + 高亮描边（不要整块 accent 实心）
  //       //   d.setColor(this.theme!.colors.cardBg);
  //       //   d.setStroke(
  //       //     dp(this.context, 1),
  //       //     this.theme!.colors.accentStroke ?? this.theme!.colors.divider,
  //       //   );
  //       //   tv.setTextColor(this.theme!.colors.text);
  //       //   try {
  //       //     tv.setTypeface(null, 1);
  //       //   } catch {}
  //       // } else {
  //       //   // ✅ 未选中：透明/很弱底
  //       //   d.setColor(0x00000000);
  //       //   d.setStroke(dp(this.context, 1), this.theme!.colors.divider);
  //       //   tv.setTextColor(this.theme!.colors.subText);
  //       //   try {
  //       //     tv.setTypeface(null, 0);
  //       //   } catch {}
  //       // }
  //       // tv.setBackgroundDrawable(d);
  //     }
  //   } catch (e) {}
  // }

  // private refreshTabsUI(): void {
  //   try {
  //     if (!this.tabContainer) return;

  //     const count = this.tabContainer.getChildCount();
  //     const tabIds = Array.from(this.tabs.keys());
  //     for (let i = 0; i < count; i++) {
  //       const tv = this.tabContainer.getChildAt(i);
  //       this.updateTabStyle(tv, tabIds[i] === this.activeTabId);
  //     }
  //   } catch (e) {}
  // }
  // private refreshTabsUI(): void {
  //   try {
  //     if (!this.tabContainer) return;

  //     const count = this.tabContainer.getChildCount();
  //     const tabIds = Array.from(this.tabs.keys());

  //     for (let i = 0; i < count; i++) {
  //       const tabItem = this.tabContainer.getChildAt(i);
  //       this.updateTabStyle(tabItem, tabIds[i] === this.activeTabId);
  //     }
  //   } catch (e) {
  //     Logger.instance.error(e);
  //   }
  // }

  private refreshTabsUI(): void {
    try {
      if (!this.tabItemMap) return;
      for (const [tabId, tabItem] of this.tabItemMap) {
        this.updateTabStyle(tabItem, tabId === this.activeTabId);
      }
    } catch (e) {
      Logger.instance.error(e);
    }
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
      Logger.instance.warn(
        "[FloatMenu] tabs is empty, tab container will be blank.",
      );
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
      // tabContainer.setPadding(
      //   dp(this.context, 10),
      //   dp(this.context, 10),
      //   dp(this.context, 10),
      //   dp(this.context, 10),
      // );
      // // tabContainer.setPadding(0, 0, 0, dp(this.context, 4)); // 你想保留底部间距就留
      // // ✅ 统一内容区留白（更像截图）
      // tabContainer.setPadding(
      //   dp(this.context, 14),
      //   dp(this.context, 14),
      //   dp(this.context, 14),
      //   dp(this.context, 18),
      // );
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
