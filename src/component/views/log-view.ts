import { API } from "../../api";
import { Logger, LogLevel } from "../../logger";
import { dp } from "../style/style";

export class LogView {
  private context: any;
  logDrawerMask: any;
  logDrawerPanel: any;
  options: any;
  menuPanelView: any;
  public isLogDrawerOpen: boolean = false;
  _loggerUnsub: any;
  logView: any;

  private width: number;
  logMaxLines: number;
  theme: any;

  constructor(
    context: any,
    width: number,
    theme: any,
    logMaxLines: number = 100,
  ) {
    this.context = context;
    this.width = width;
    this.logMaxLines = logMaxLines;
    this.theme = theme;
    this.createView();
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
        self.addLogToView(it.level, it.message);
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

  private addLogToView(level: LogLevel, message: string): void {
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

    // 入队（非常轻）
    this._logPending.push(`[${level}] ${message}`);

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
    });
  }

  private createView() {
    if (this.logDrawerMask && this.logDrawerPanel) return;

    const FrameLayout = API.FrameLayout;
    const LinearLayout = API.LinearLayout;
    const FrameLayoutParams = API.FrameLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const Gravity = API.Gravity;
    const GradientDrawable = API.GradientDrawable;
    const Color = API.Color;
    const View = API.View;

    const self = this;
    const ctx = this.context;

    // 抽屉宽度：建议固定 dp，避免跟随窗口缩放导致抖动
    const drawerW = dp(ctx, this.width - 80);

    // ===== 1) 全屏遮罩（覆盖整个悬浮窗根容器）=====
    const mask = FrameLayout.$new(ctx);
    mask.setLayoutParams(
      FrameLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );
    mask.setVisibility(View.GONE.value);
    mask.setClickable(true);

    // 半透明遮罩
    try {
      mask.setBackgroundColor(Color.parseColor("#66000000"));
    } catch {
      mask.setBackgroundColor(0x66000000);
    }

    // 点击遮罩关闭
    mask.setOnClickListener(
      Java.registerClass({
        name: "LogDrawerMaskClickListener" + Date.now(),
        implements: [API.OnClickListener],
        methods: {
          onClick: function () {
            self.closeLogDrawer();
          },
        },
      }).$new(),
    );

    // ===== 2) 右侧抽屉面板 =====
    const panel = LinearLayout.$new(ctx);
    panel.setOrientation(1); // VERTICAL

    const panelLp = FrameLayoutParams.$new(
      this.width - 80,
      ViewGroupLayoutParams.MATCH_PARENT.value,
    );
    panelLp.gravity.value = Gravity.END.value | Gravity.TOP.value;
    panel.setLayoutParams(panelLp);

    // 背景：圆角卡片
    const bg = GradientDrawable.$new();
    bg.setCornerRadius(dp(ctx, 14));
    bg.setColor(this.theme.colors.cardBg);
    bg.setStroke(dp(ctx, 1), this.theme.colors.divider);
    panel.setBackgroundDrawable(bg);
    panel.setPadding(dp(ctx, 8), dp(ctx, 8), dp(ctx, 8), dp(ctx, 8));

    // 初始放在右侧屏外（关闭状态）
    panel.setTranslationX(drawerW);

    // ===== 3) 内部日志内容：复用你 createLogView（高性能版）=====
    const logRoot = this.createLogView(); // ScrollView
    logRoot.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      ),
    );
    panel.addView(logRoot);

    this.bindLoggerToLogViewOnce();
    // 组装
    mask.addView(panel);

    Java.scheduleOnMainThread(() => {
      try {
        // 关键：加到 menuContainerView 的最后，天然在最上层
        this.parentView.addView(mask);

        // 再保险：bringToFront + elevation
        try {
          mask.bringToFront();
        } catch {}
        try {
          panel.bringToFront();
        } catch {}
        try {
          mask.setElevation(9999);
        } catch {}
        try {
          panel.setElevation(10000);
        } catch {}
      } catch (e) {
        console.error("ensureLogDrawer failed: " + e);
      }
    });

    this.logDrawerMask = mask;
    this.logDrawerPanel = panel;
  }

  /**
   * 展开抽屉
   * @returns
   */
  public openLogDrawer(): void {
    if (!this.logDrawerMask || !this.logDrawerPanel) return;

    const View = API.View;
    this.isLogDrawerOpen = true;

    Java.scheduleOnMainThread(() => {
      try {
        this.logDrawerMask!.setVisibility(View.VISIBLE.value);
        this.logDrawerMask!.bringToFront();
        this.logDrawerPanel!.bringToFront();

        // 轻量动画：translationX
        try {
          this.logDrawerPanel!.animate()
            .translationX(0)
            .setDuration(180)
            .start();
        } catch {
          this.logDrawerPanel!.setTranslationX(0);
        }
      } catch (e) {
        console.error("openLogDrawer failed: " + e);
      }
    });
  }

  /**
   * 关闭抽屉
   * @returns
   */
  public closeLogDrawer(): void {
    if (!this.logDrawerMask || !this.logDrawerPanel) return;

    const View = API.View;
    const drawerW = dp(this.context, this.width - 80);
    this.isLogDrawerOpen = false;

    Java.scheduleOnMainThread(() => {
      try {
        // 动画结束隐藏 mask（避免它挡住悬浮窗交互）
        try {
          this.logDrawerPanel!.animate()
            .translationX(drawerW)
            .setDuration(160)
            .withEndAction(
              Java.registerClass({
                name:
                  "LogDrawerCloseEndAction" +
                  Date.now() +
                  Math.random().toString(36).substring(4),
                implements: [Java.use("java.lang.Runnable")],
                methods: {
                  run: () => {
                    this.logDrawerMask!.setVisibility(View.GONE.value);
                  },
                },
              }).$new(),
            )
            .start();
        } catch {
          this.logDrawerPanel!.setTranslationX(drawerW);
          this.logDrawerMask!.setVisibility(View.GONE.value);
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
      console.error("createLogView setFillViewport failed: " + e);
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
