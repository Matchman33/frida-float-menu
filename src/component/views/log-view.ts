import { API } from "../../api";
import { Logger, LogLevel } from "../../logger";
import { dp } from "../style/style";

export class LogView {
  private context: any;
  private logDrawerPanel: any;
  public isLogDrawerOpen: boolean = false;
  private _loggerUnsub: any;
  private logView: any;
  private logMaxLines: number;
  private theme: any;
  private parentView: any;
  private height: number;
  logScrollView: any;

  constructor(
    context: any,
    height: number,
    theme: any,
    logMaxLines: number = 100,
  ) {
    this.context = context;
    this.height = height;
    this.logMaxLines = logMaxLines;
    this.theme = theme;
  }
  // ensureLogDrawer() 里：创建完 logViewRoot / this.logView 之后调用一次
  private bindLoggerToLogViewOnce(): void {
    if (this._loggerUnsub) return;

    // 这里按你的 Logger 文件导入方式写：如果你没用 import，就改成全局引用
    // import { Logger } from "./logger";
    const self = this;

    this._loggerUnsub = Logger.instance.onLog((items) => {
      // 注意：items 是一批，千万别每条 scheduleOnMainThread 做 UI
      // 直接循环调用 addLogToView（它内部会入队并节流到一次 UI 刷新）
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        self.addLogToView(it.level, it.message, it.ts);
      }
    }, true);
  }

  /**
   * Add log message to log view
   */
  private _logMaxLinesCache: number = 0;
  private _logRing: string[] | null = null;
  private _logHead: number = 0; // 下一次写入位置
  private _logSize: number = 0; // 当前有效行数
  private _logPending: string[] = [];
  private _logFlushScheduled: boolean = false;

  private addLogToView(level: LogLevel, message: string, ts: number): void {
    if (!this.logView) return;

    const maxLines = this.logMaxLines | 0;
    if (maxLines <= 0) return;

    // 初始化/变更容量时重建环形缓冲
    if (!this._logRing || this._logMaxLinesCache !== maxLines) {
      this._logMaxLinesCache = maxLines;
      this._logRing = new Array(maxLines);
      this._logHead = 0;
      this._logSize = 0;
      this._logPending.length = 0;
      this._logFlushScheduled = false;
      // 清屏
      this.logView.setText(API.JString.$new(""));
    }

    // 入队（非常轻），添加事件，只要时分秒
    this._logPending.push(
      `[${level.toUpperCase()} ${new Date(ts).toTimeString().substring(0, 8)}] ${message}`,
    );

    // 节流：同一“帧/短时间”只安排一次刷新
    if (this._logFlushScheduled) return;
    this._logFlushScheduled = true;

    Java.scheduleOnMainThread(() => {
      this._logFlushScheduled = false;
      if (!this.logView || !this._logRing) return;

      // 把 pending 批量写进环形缓冲
      while (this._logPending.length > 0) {
        const line = this._logPending.shift() as string;
        this._logRing[this._logHead] = line;
        this._logHead = (this._logHead + 1) % this._logMaxLinesCache;
        if (this._logSize < this._logMaxLinesCache) this._logSize++;
      }

      // 一次性拼接输出（只做一次 join，不做 split）
      let out = "";
      const start =
        (this._logHead - this._logSize + this._logMaxLinesCache) %
        this._logMaxLinesCache;
      for (let i = 0; i < this._logSize; i++) {
        const idx = (start + i) % this._logMaxLinesCache;
        const s = this._logRing[idx];
        if (s == null) continue;
        out += s;
        if (i !== this._logSize - 1) out += "\n";
      }

      this.logView.setText(API.JString.$new(out));
      // try {
      //   const sv = this.logScrollView; // ScrollView
      //   const View = API.View;

      //   sv.post(
      //     Java.registerClass({
      //       name: "LogScrollToBottom" + Date.now(),
      //       implements: [Java.use("java.lang.Runnable")],
      //       methods: {
      //         run: function () {
      //           try {
      //             sv.fullScroll(View.FOCUS_DOWN.value);
      //           } catch {}
      //         },
      //       },
      //     }).$new(),
      //   );
      // } catch {}
    });
  }

  public createViewOnce(parentView: any) {
    if (!parentView) {
      Logger.instance.error("LogView: parentView is null");
      return;
    }
    this.parentView = parentView;
    if (this.logDrawerPanel) return;
    const LinearLayout = API.LinearLayout;
    const FrameLayoutParams = API.FrameLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const Gravity = API.Gravity;
    const GradientDrawable = API.GradientDrawable;

    const ctx = this.context;

    // 防裁剪
    try {
      this.parentView.setClipChildren(false);
    } catch {}
    try {
      this.parentView.setClipToPadding(false);
    } catch {}

    // ===== panel：底部弹出面板 =====
    const panel = LinearLayout.$new(this.context);
    panel.setOrientation(LinearLayout.VERTICAL.value);

    const panelLp = FrameLayoutParams.$new(
      // this.width,
      ViewGroupLayoutParams.MATCH_PARENT.value,
      // ViewGroupLayoutParams.MATCH_PARENT.value,
      this.height,
    );
    panelLp.gravity.value = Gravity.BOTTOM.value; // ✅ 底部
    panel.setLayoutParams(panelLp);

    panel.setAlpha(0.9);
    const bg = GradientDrawable.$new();
    bg.setCornerRadius(dp(ctx, 14));
    bg.setColor(this.theme.colors.cardBg);
    bg.setStroke(dp(ctx, 1), this.theme.colors.divider);
    panel.setBackgroundDrawable(bg);
    panel.setPadding(dp(ctx, 8), dp(ctx, 8), dp(ctx, 8), dp(ctx, 8));

    // 初始在屏幕下方（关闭状态）
    try {
      panel.setTranslationY(this.height);
    } catch {}

    // Z 置顶（防 TabLayout/RecyclerView elevation 盖住）
    // try {
    //   mask.setElevation(100000);
    // } catch {}
    try {
      panel.setElevation(100001);
    } catch {}
    // try {
    //   mask.setTranslationZ(100000);
    // } catch {}
    try {
      panel.setTranslationZ(100001);
    } catch {}

    // ===== 3) 内部日志内容：复用你 createLogView（高性能版）=====
    const logRoot = this.createLogView(); // ScrollView
    logRoot.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );
    this.logScrollView = logRoot;
    panel.addView(logRoot);

    this.bindLoggerToLogViewOnce();
    // 组装
    // mask.addView(panel);

    Java.scheduleOnMainThread(() => {
      try {
        // 关键：加到 menuContainerView 的最后，天然在最上层
        this.parentView.addView(panel);

        // 再保险：bringToFront + elevation
        // try {
        //   mask.bringToFront();
        // } catch {}
        try {
          panel.bringToFront();
        } catch {}
      } catch (e) {
        Logger.instance.error("ensureLogDrawer failed: " + e);
      }
    });

    // this.logDrawerPanel = mask;
    this.logDrawerPanel = panel;
  }

  /**
   * 展开抽屉
   * @returns
   */
  public openLogDrawer(): void {
    if (!this.logDrawerPanel) return;

    const View = API.View;
    this.isLogDrawerOpen = true;

    Java.scheduleOnMainThread(() => {
      try {
        this.logDrawerPanel!.setVisibility(View.VISIBLE.value);
        // 每次打开都置顶
        try {
          this.logDrawerPanel!.bringToFront();
        } catch {}

        // 动画：Y 从 height -> 0
        try {
          this.logDrawerPanel!.animate()
            .translationY(0)
            .setDuration(180)
            .start();
        } catch {
          this.logDrawerPanel!.setTranslationY(0);
        }
      } catch {}
    });
  }

  /**
   * 关闭抽屉
   * @returns
   */
  public closeLogDrawer(): void {
    // if (!this.logDrawerPanel || !this.logDrawerPanel) return;

    const View = API.View;
    this.isLogDrawerOpen = false;

    const endAction = Java.registerClass({
      name:
        "LogBottomCloseEnd" +
        Date.now() +
        Math.random().toString(36).substring(4),
      implements: [Java.use("java.lang.Runnable")],
      methods: {
        run: () => {
          try {
            this.logDrawerPanel!.setVisibility(View.GONE.value);
          } catch {}
        },
      },
    }).$new();

    Java.scheduleOnMainThread(() => {
      try {
        // 动画：Y 到 height，结束隐藏 mask
        try {
          this.logDrawerPanel!.animate()
            .translationY(this.height)
            .setDuration(160)
            .withEndAction(endAction)
            .start();
        } catch {
          this.logDrawerPanel!.setTranslationY(this.height);
          this.logDrawerPanel!.setVisibility(View.GONE.value);
        }
      } catch {}
    });
  }

  /**
   * 创建日志视图（高性能版）
   * - 使用环形缓冲保存最近 N 行（N = options.logMaxLines）
   * - 日志追加时只入队，不立刻 setText
   * - 用 scheduleOnMainThread 做“批量刷新”（最多每帧一次），避免卡顿
   * - this.logView 会指向内部 TextView，供 clearLogs() 等复用
   *
   * 返回：日志面板根视图（ScrollView）
   */
  private createLogView(): any {
    const ScrollView = API.ScrollView;
    const TextView = API.TextView;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const LinearLayoutParams = API.LinearLayoutParams;
    const JString = API.JString;
    const Gravity = API.Gravity;

    // 根：ScrollView
    const sv = ScrollView.$new(this.context);
    sv.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );
    try {
      sv.setFillViewport(true);
      sv.setVerticalScrollBarEnabled(false);
      sv.setBackgroundColor(0x00000000);
    } catch (e) {
      Logger.instance.error("createLogView setFillViewport failed: " + e);
    }

    // 内容：TextView
    const tv = TextView.$new(this.context);
    tv.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    // 字体/颜色：走主题，尽量轻量
    tv.setTextColor(this.theme.colors.text);
    tv.setTextSize(2, this.theme.textSp.body);
    tv.setGravity(Gravity.START.value);
    tv.setIncludeFontPadding(false);
    tv.setPadding(
      dp(this.context, 10),
      dp(this.context, 8),
      dp(this.context, 10),
      dp(this.context, 8),
    );
    tv.setText(JString.$new(""));

    sv.addView(tv);

    // 绑定到类字段，兼容你现有 clearLogs() 使用 this.logView.setText(...) :contentReference[oaicite:1]{index=1}
    this.logView = tv;

    return sv;
  }
}
