import Java from "frida-java-bridge";
import { API } from "../../api.js";
import { ConstantConfig } from "../../constant-config.js";
import { Logger, LogLevel } from "../../logger.js";
import { logicalToWindow, windowToLogical } from "../../utils.js";
import { dp } from "../style/style.js";

export class LogViewWindow {
  private menu: any;
  private context: any;
  private windowManager: any;
  private theme: any;
  private logMaxLines: number;

  private windowRoot: any = null;
  private windowParams: any = null;
  private titleDragHandle: any = null;
  private logView: any = null;

  private isCreated: boolean = false;
  private isCreating: boolean = false;
  private isAttached: boolean = false;

  public isLogWindowVisible: boolean = false;

  private _loggerUnsub: any = null;
  private _logMaxLinesCache: number = 0;
  private _logRing: string[] | null = null;
  private _logHead: number = 0;
  private _logSize: number = 0;
  private _logPending: string[] = [];
  private _logFlushScheduled: boolean = false;

  private _onCloseButtonClick: (() => void) | null = null;
  private width?: number;
  private height?: number;
  lastTouchX: any;
  lastTouchY: any;

  constructor(
    context: any,
    theme: any,
    menu: any,
    logMaxLines: number = 100,
    onCloseButtonClick?: () => void,
  ) {
    this.context = context;
    this.theme = theme;
    this.menu = menu;
    this.logMaxLines = logMaxLines;
    this._onCloseButtonClick = onCloseButtonClick ?? null;

    const Context = API.Context;
    this.windowManager = Java.cast(
      this.context.getSystemService(Context.WINDOW_SERVICE.value),
      API.ViewManager,
    );
  }

  public setOnCloseButtonClick(callback: (() => void) | null): void {
    this._onCloseButtonClick = callback ?? null;
  }

  private bindLoggerToLogViewOnce(): void {
    if (this._loggerUnsub) return;

    this._loggerUnsub = Logger.instance.onLog((items) => {
      for (let i = 0; i < items.length; i++) {
        const it = items[i];
        this.addLogToView(it.level, it.message, it.ts);
      }
    }, true);
  }

  private addLogToView(level: LogLevel, message: string, ts: number): void {
    if (!this.logView) return;

    const maxLines = this.logMaxLines | 0;
    if (maxLines <= 0) return;

    if (!this._logRing || this._logMaxLinesCache !== maxLines) {
      this._logMaxLinesCache = maxLines;
      this._logRing = new Array(maxLines);
      this._logHead = 0;
      this._logSize = 0;
      this._logPending.length = 0;
      this._logFlushScheduled = false;

      try {
        this.logView.setText(API.JString.$new(""));
      } catch {}
    }

    const t = new Date(ts).toTimeString().substring(0, 8);
    this._logPending.push(`[${t}:${level}] ${message}`);

    if (this._logFlushScheduled) return;
    this._logFlushScheduled = true;

    Java.scheduleOnMainThread(() => {
      this._logFlushScheduled = false;
      if (!this.logView || !this._logRing) return;

      while (this._logPending.length > 0) {
        const line = this._logPending.shift() as string;
        this._logRing[this._logHead] = line;
        this._logHead = (this._logHead + 1) % this._logMaxLinesCache;
        if (this._logSize < this._logMaxLinesCache) this._logSize++;
      }

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

      try {
        this.logView.setText(API.JString.$new(out));
      } catch (e) {
        Logger.instance.error("flush log text failed: " + e);
      }
    });
  }

  private buildWindowType(): number {
    const LayoutParams = API.LayoutParams;

    // 你当前环境里 2038 已验证可显示，就继续沿用
    // 如果后面某些环境权限有问题，再统一改这里
    return LayoutParams.TYPE_APPLICATION_OVERLAY.value;
  }

  private createWindowOnce(): void {
    if (this.isCreated || this.isCreating || this.windowRoot) return;
    this.isCreating = true;

    const self = this;

    const LinearLayout = API.LinearLayout;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const TextView = API.TextView;
    const ScrollView = API.ScrollView;
    const GradientDrawable = API.GradientDrawable;
    const Gravity = API.Gravity;
    const JString = API.JString;
    const LayoutParams = API.LayoutParams;
    const View = API.View;
    const FrameLayout = API.FrameLayout;
    const FrameLayoutParams = API.FrameLayoutParams;
    const PixelFormat = Java.use("android.graphics.PixelFormat");

    try {
      // ========================
      // parent：真正挂到 WindowManager 的根
      // ========================
      const root = FrameLayout.$new(this.context);
      const parentLp = FrameLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      );
      root.setLayoutParams(parentLp);
      root.setBackgroundColor(0x00000000);
      root.setClickable(false);
      root.setFocusable(false);

      // ========================
      // root：实际显示内容
      // ========================
      const panel = LinearLayout.$new(this.context);
      panel.setOrientation(LinearLayout.VERTICAL.value);
      panel.setClickable(true);
      panel.setFocusable(false);

      const rootLp = FrameLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.MATCH_PARENT.value,
      );
      panel.setLayoutParams(rootLp);

      // 主体背景：更接近图里的蓝黑科技风，同时增加透明度
      const rootBg = GradientDrawable.$new();
      rootBg.setCornerRadius(dp(this.context, 12));
      rootBg.setColor(0xb80b1324 | 0); // 半透明深蓝黑
      rootBg.setStroke(dp(this.context, 1.2), 0xff1f63ff | 0); // 蓝色描边
      panel.setBackgroundDrawable(rootBg);

      try {
        panel.setElevation(100010);
        panel.setTranslationZ(100010);
      } catch {}

      // ========================
      // Header
      // ========================
      const header = LinearLayout.$new(this.context);
      header.setOrientation(LinearLayout.HORIZONTAL.value);
      header.setGravity(Gravity.CENTER_VERTICAL.value);
      header.setPadding(
        dp(this.context, 14),
        dp(this.context, 11),
        dp(this.context, 14),
        dp(this.context, 11),
      );

      const headerBg = GradientDrawable.$new();
      headerBg.setColor(0xcc102347 | 0); // 更深一点的蓝
      headerBg.setCornerRadii([
        dp(this.context, 12),
        dp(this.context, 12),
        dp(this.context, 12),
        dp(this.context, 12),
        0,
        0,
        0,
        0,
      ]);
      header.setBackgroundDrawable(headerBg);

      const title = TextView.$new(this.context);
      title.setText(JString.$new("系统日志"));
      title.setTextColor(0xff1f7bff | 0);
      try {
        title.setTypeface(null, 1);
      } catch {}
      title.setTextSize(2, this.theme?.textSp?.title ?? 15);
      title.setLayoutParams(
        LinearLayoutParams.$new(
          0,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
          1.0,
        ),
      );

      const dots = TextView.$new(this.context);
      dots.setText(JString.$new("●  ●  ●"));
      dots.setTextColor(0xff4a5e80 | 0);
      dots.setTextSize(2, this.theme?.textSp?.caption ?? 11);

      header.addView(title);
      header.addView(dots);

      // ========================
      // 中间日志区域
      // ========================
      const scrollView = ScrollView.$new(this.context);
      scrollView.setLayoutParams(
        LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          0,
          1.0,
        ),
      );

      try {
        scrollView.setFillViewport(true);
        scrollView.setVerticalScrollBarEnabled(false);
        scrollView.setBackgroundColor(0x00000000);
      } catch {}

      const logText = TextView.$new(this.context);
      logText.setLayoutParams(
        ViewGroupLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        ),
      );
      logText.setTextColor(0xffeaf2ff | 0);
      logText.setTextSize(2, this.theme?.textSp?.body ?? 13);
      logText.setPadding(
        dp(this.context, 14),
        dp(this.context, 12),
        dp(this.context, 14),
        dp(this.context, 12),
      );
      logText.setLineSpacing(0, 1.08);
      logText.setText(JString.$new(""));
      scrollView.addView(logText);

      // ========================
      // Footer
      // ========================
      const footer = LinearLayout.$new(this.context);
      footer.setOrientation(LinearLayout.HORIZONTAL.value);
      footer.setGravity(Gravity.END.value | Gravity.CENTER_VERTICAL.value);
      footer.setPadding(
        dp(this.context, 12),
        dp(this.context, 10),
        dp(this.context, 12),
        dp(this.context, 10),
      );

      const footerBg = GradientDrawable.$new();
      footerBg.setColor(0xb8101d36 | 0);
      footer.setBackgroundDrawable(footerBg);

      const clearBtn = TextView.$new(this.context);
      clearBtn.setText(JString.$new("清除"));
      try {
        clearBtn.setTypeface(null, 1);
      } catch {}
      clearBtn.setTextColor(0xff9aaaca | 0);
      clearBtn.setTextSize(2, this.theme?.textSp?.caption ?? 12);
      clearBtn.setGravity(Gravity.CENTER.value);
      clearBtn.setPadding(
        dp(this.context, 18),
        dp(this.context, 9),
        dp(this.context, 18),
        dp(this.context, 9),
      );

      const clearBg = GradientDrawable.$new();
      clearBg.setCornerRadius(dp(this.context, 6));
      clearBg.setColor(0x00112233 | 0);
      clearBtn.setBackgroundDrawable(clearBg);

      const closeBtn = TextView.$new(this.context);
      closeBtn.setText(JString.$new("隐藏"));
      try {
        closeBtn.setTypeface(null, 1);
      } catch {}
      closeBtn.setTextColor(0xffffffff | 0);
      closeBtn.setTextSize(2, this.theme?.textSp?.caption ?? 12);
      closeBtn.setGravity(Gravity.CENTER.value);
      closeBtn.setPadding(
        dp(this.context, 20),
        dp(this.context, 10),
        dp(this.context, 20),
        dp(this.context, 10),
      );

      const closeBg = GradientDrawable.$new();
      closeBg.setCornerRadius(dp(this.context, 6));
      closeBg.setColor(0xff1b66ff | 0);
      closeBg.setStroke(dp(this.context, 1), 0xff2f86ff | 0);
      closeBtn.setBackgroundDrawable(closeBg);

      const clearLp = LinearLayoutParams.$new(
        LinearLayoutParams.WRAP_CONTENT.value,
        LinearLayoutParams.WRAP_CONTENT.value,
      );
      clearLp.setMargins(0, 0, dp(this.context, 10), 0);
      clearBtn.setLayoutParams(clearLp);

      footer.addView(clearBtn);
      footer.addView(closeBtn);

      panel.addView(header);
      panel.addView(scrollView);
      panel.addView(footer);

      root.addView(panel, rootLp);

      // 尺寸比之前大一点
      const width = dp(this.context, 320);
      const height = dp(this.context, 290);
      this.width = width;
      this.height = height;
      const params = LayoutParams.$new(
        width,
        height,
        0,
        0,
        this.buildWindowType(),
        LayoutParams.FLAG_NOT_FOCUSABLE.value |
          LayoutParams.FLAG_NOT_TOUCH_MODAL.value,
        PixelFormat.TRANSLUCENT.value,
      );

      this.logView = logText;
      this.windowRoot = root;
      this.windowParams = params;
      this.titleDragHandle = header;
      this.isCreated = true;

      clearBtn.setOnClickListener(
        Java.registerClass({
          name:
            "LogClearClick" + Date.now() + Math.random().toString(36).slice(2),
          implements: [API.OnClickListener],
          methods: {
            onClick: function () {
              try {
                self._logRing = new Array(
                  self._logMaxLinesCache || self.logMaxLines,
                );
                self._logHead = 0;
                self._logSize = 0;
                self._logPending.length = 0;
                if (self.logView) {
                  self.logView.setText(JString.$new(""));
                }
              } catch (e) {
                Logger.instance.error("clear log failed: " + e);
              }
            },
          },
        }).$new(),
      );

      closeBtn.setOnClickListener(
        Java.registerClass({
          name:
            "LogCloseClick" + Date.now() + Math.random().toString(36).slice(2),
          implements: [API.OnClickListener],
          methods: {
            onClick: function () {
              self.closeLogWindow();
              try {
                if (self._onCloseButtonClick) {
                  self._onCloseButtonClick();
                }
              } catch (e) {
                Logger.instance.error("close callback failed: " + e);
              }
            },
          },
        }).$new(),
      );

      try {
        root.setVisibility(View.GONE.value);
      } catch {}

      this.addDragListener(
        this.titleDragHandle,
        this.windowRoot,
        this.windowParams,
        () => this.isLogWindowVisible,

      );

      this.bindLoggerToLogViewOnce();

      Logger.instance.debug(
        `log window created: width=${width}, height=${height}, x=${params.x.value}, y=${params.y.value}`,
      );
    } catch (e) {
      Logger.instance.error("create log window ui failed: " + e);
      this.isCreated = false;
      this.windowRoot = null;
      this.windowParams = null;
      this.titleDragHandle = null;
      this.logView = null;
    } finally {
      this.isCreating = false;
    }
  }

  private attachWindowIfNeeded(): void {
    const self = this;
    const View = API.View;

    if (!this.windowRoot || !this.windowParams) return;
    if (this.isAttached) return;

    Java.scheduleOnMainThread(() => {
      try {
        if (!self.windowRoot || !self.windowParams || self.isAttached) return;

        Logger.instance.debug(
          `attach log window: x=${self.windowParams.x.value}, y=${self.windowParams.y.value}, width=${self.windowParams.width.value}, height=${self.windowParams.height.value}, type=${self.windowParams.type.value}`,
        );

        self.windowManager.addView(self.windowRoot, self.windowParams);
        self.isAttached = true;

        if (self.isLogWindowVisible) {
          try {
            self.windowRoot.setVisibility(View.VISIBLE.value);
          } catch {}
        }

        Logger.instance.info("attach log window success");
      } catch (e) {
        Logger.instance.error("attach log window failed: " + e);
      }
    });
  }


  private addDragListener(
    targetView: any,
    window: any,
    winParams: any,
    isShowing: () => boolean,
  ) {
    const OnTouchListener = API.OnTouchListener;
    const MotionEvent = API.MotionEvent;
    targetView.setClickable(true);
    const getBounds = () => {
      const w = this.width!;
      const h = this.height!;
      return {
        left: 0,
        top: -40,
        right: ConstantConfig.screenWidth - w,
        bottom: ConstantConfig.screenHeight - h,
      };
    };
    const self = this;

    let isDragging = false;
    const DRAG_THRESHOLD = 5;

    // 在 addDragListener 里加两个局部变量（闭包变量）
    let touchOffsetX = 0;
    let touchOffsetY = 0;
    const touchListener = Java.registerClass({
      name:
        "com.frida.FloatDragListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [OnTouchListener],
      methods: {
        onTouch: function (v: any, event: any) {
          const action = event.getAction();
          switch (action) {
            case MotionEvent.ACTION_DOWN.value: {
              isDragging = false;

              const rawX = event.getRawX();
              const rawY = event.getRawY();

              // 当前窗口位置（注意：这里的 winParams.x/y 是“window坐标”）
              const startWx = winParams.x.value;
              const startWy = winParams.y.value;

              // 记录手指按下点相对窗口左上角的偏移（window坐标系内）
              touchOffsetX = rawX - startWx;
              touchOffsetY = rawY - startWy;

              // 记录 down 时的位置，用于阈值判断
              self.lastTouchX = rawX;
              self.lastTouchY = rawY;

              return true;
            }

            case MotionEvent.ACTION_MOVE.value: {
              const rawX = event.getRawX();
              const rawY = event.getRawY();

              const dx = rawX - self.lastTouchX;
              const dy = rawY - self.lastTouchY;
              if (
                !isDragging &&
                (Math.abs(dx) > DRAG_THRESHOLD || Math.abs(dy) > DRAG_THRESHOLD)
              ) {
                isDragging = true;
              }

              if (isDragging) {
                // 直接由手指位置反推窗口左上角（不会积累漂移）
                let wx = rawX - touchOffsetX;
                let wy = rawY - touchOffsetY;
                // window → logical（如果你当前还在用 logical 做边界）
                const p = windowToLogical(wx, wy, self.width!, self.height!);

                let newX = p.x;
                let newY = p.y;

                const bounds = getBounds();
                newX = Math.max(bounds.left, Math.min(bounds.right, newX));
                newY = Math.max(bounds.top, Math.min(bounds.bottom, newY));
                if (isShowing()) {
                  self.updatePosition(window, winParams, { x: newX, y: newY });
                }
              }

              return true;
            }

            case MotionEvent.ACTION_UP.value:
            case MotionEvent.ACTION_CANCEL.value: {
              return true;
            }
          }
        },
      },
    });

    targetView.setOnTouchListener(touchListener.$new());
  }
  private updatePosition(
    window: any,
    winParams: any,
    newPos: { x: number; y: number },
  ): void {
    const { x: wx, y: wy } = logicalToWindow(
      newPos.x,
      newPos.y,
      this.width!,
      this.height!,
    );

    winParams.x.value = wx | 0;
    winParams.y.value = wy | 0;
    Java.scheduleOnMainThread(() => {
      this.windowManager.updateViewLayout(window, winParams);
    });

    // 刷新
  }
  public openLogWindow(): void {
    const self = this;
    const View = API.View;

    this.isLogWindowVisible = true;
    this.createWindowOnce();
    this.attachWindowIfNeeded();

    Java.scheduleOnMainThread(() => {
      try {
        if (!self.windowRoot) return;

        self.windowRoot.setVisibility(View.VISIBLE.value);

        if (self.isAttached) {
          try {
            self.windowManager.updateViewLayout(
              self.windowRoot,
              self.windowParams,
            );
          } catch {}
        }

        Logger.instance.debug("open log window success");
      } catch (e) {
        Logger.instance.error("open log window failed: " + e);
      }
    });
  }

  public closeLogWindow(): void {
    this.isLogWindowVisible = false;
    if (!this.windowRoot) return;

    const self = this;
    const View = API.View;

    Java.scheduleOnMainThread(() => {
      try {
        if (!self.windowRoot) return;
        self.windowRoot.setVisibility(View.GONE.value);
        Logger.instance.debug("close log window success");
      } catch (e) {
        Logger.instance.error("close log window failed: " + e);
      }
    });
  }

  public destroy(): void {
    const self = this;

    this.isLogWindowVisible = false;

    if (this._loggerUnsub) {
      try {
        this._loggerUnsub();
      } catch {}
      this._loggerUnsub = null;
    }

    Java.scheduleOnMainThread(() => {
      try {
        if (self.windowRoot && self.isAttached) {
          self.windowManager.removeView(self.windowRoot);
        }
      } catch (e) {
        Logger.instance.error("destroy remove log window failed: " + e);
      } finally {
        self.windowRoot = null;
        self.windowParams = null;
        self.titleDragHandle = null;
        self.logView = null;
        self.isCreated = false;
        self.isCreating = false;
        self.isAttached = false;
      }
    });
  }
}
