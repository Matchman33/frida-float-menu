import { API } from "../../api";
import { Logger, LogLevel } from "../../logger";
import { dp } from "../style/style";

export class LogViewWindow {
  private context: any;
  private windowManager: any;
  private theme: any;
  private logMaxLines: number;
  private windowRoot: any = null;
  private windowParams: any = null;
  private titleDragHandle: any = null;
  private logView: any = null;
  private isCreated: boolean = false;
  public isLogWindowVisible: boolean = false;

  private _loggerUnsub: any;
  private _logMaxLinesCache: number = 0;
  private _logRing: string[] | null = null;
  private _logHead: number = 0;
  private _logSize: number = 0;
  private _logPending: string[] = [];
  private _logFlushScheduled: boolean = false;

  constructor(context: any, theme: any, logMaxLines: number = 100) {
    this.context = context;
    this.theme = theme;
    this.logMaxLines = logMaxLines;

    const Context = API.Context;
    this.windowManager = Java.cast(
      this.context.getSystemService(Context.WINDOW_SERVICE.value),
      API.ViewManager,
    );
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
      this.logView.setText(API.JString.$new(""));
    }

    const t = new Date(ts).toTimeString().substring(0, 8);
    this._logPending.push(`[${t}] ${level.toUpperCase()} ${message}`);

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

      this.logView.setText(API.JString.$new(out));
    });
  }

  public createWindowOnce(): void {
    if (this.isCreated) return;

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

    const root = LinearLayout.$new(this.context);
    root.setOrientation(LinearLayout.VERTICAL.value);

    const rootBg = GradientDrawable.$new();
    rootBg.setCornerRadius(dp(this.context, 12));
    rootBg.setColor(this.theme.colors.overlayBg);
    rootBg.setStroke(dp(this.context, 1), this.theme.colors.accentStroke);
    root.setBackgroundDrawable(rootBg);

    try {
      root.setElevation(100010);
      root.setTranslationZ(100010);
    } catch {}

    const header = LinearLayout.$new(this.context);
    header.setOrientation(LinearLayout.HORIZONTAL.value);
    header.setGravity(Gravity.CENTER_VERTICAL.value);
    header.setPadding(dp(this.context, 12), dp(this.context, 10), dp(this.context, 12), dp(this.context, 10));

    const headerBg = GradientDrawable.$new();
    headerBg.setColor(this.theme.colors.cardBg);
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
    title.setText(JString.$new("SYSTEM LOG"));
    title.setTextColor(this.theme.colors.accent);
    title.setTypeface(null, 1);
    title.setTextSize(2, this.theme.textSp.title);
    title.setLayoutParams(
      LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0),
    );

    const dots = TextView.$new(this.context);
    dots.setText(JString.$new("● ● ●"));
    dots.setTextColor(this.theme.colors.subText);
    dots.setTextSize(2, this.theme.textSp.caption);

    header.addView(title);
    header.addView(dots);

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
    logText.setTextColor(this.theme.colors.text);
    logText.setTextSize(2, this.theme.textSp.body);
    logText.setPadding(dp(this.context, 12), dp(this.context, 10), dp(this.context, 12), dp(this.context, 10));
    logText.setText(JString.$new(""));
    scrollView.addView(logText);

    const footer = LinearLayout.$new(this.context);
    footer.setOrientation(LinearLayout.HORIZONTAL.value);
    footer.setGravity(Gravity.END.value | Gravity.CENTER_VERTICAL.value);
    footer.setPadding(dp(this.context, 10), dp(this.context, 8), dp(this.context, 10), dp(this.context, 10));

    const clearBtn = TextView.$new(this.context);
    clearBtn.setText(JString.$new("CLEAR"));
    clearBtn.setTypeface(null, 1);
    clearBtn.setTextColor(this.theme.colors.subText);
    clearBtn.setTextSize(2, this.theme.textSp.caption);
    clearBtn.setPadding(dp(this.context, 12), dp(this.context, 6), dp(this.context, 12), dp(this.context, 6));

    const closeBtn = TextView.$new(this.context);
    closeBtn.setText(JString.$new("CLOSE LOG"));
    closeBtn.setTypeface(null, 1);
    closeBtn.setTextColor(this.theme.colors.buttonText || this.theme.colors.text);
    closeBtn.setTextSize(2, this.theme.textSp.caption);
    closeBtn.setPadding(dp(this.context, 16), dp(this.context, 8), dp(this.context, 16), dp(this.context, 8));
    const closeBg = GradientDrawable.$new();
    closeBg.setCornerRadius(dp(this.context, 6));
    closeBg.setColor(this.theme.colors.accent);
    closeBtn.setBackgroundDrawable(closeBg);

    const clearLp = LinearLayoutParams.$new(
      LinearLayoutParams.WRAP_CONTENT.value,
      LinearLayoutParams.WRAP_CONTENT.value,
    );
    clearLp.setMargins(0, 0, dp(this.context, 10), 0);
    clearBtn.setLayoutParams(clearLp);

    footer.addView(clearBtn);
    footer.addView(closeBtn);

    root.addView(header);
    root.addView(scrollView);
    root.addView(footer);

    const width = dp(this.context, 320);
    const height = dp(this.context, 300);
    const params = LayoutParams.$new(
      width,
      height,
      dp(this.context, 20),
      dp(this.context, 60),
      2038,
      LayoutParams.FLAG_NOT_FOCUSABLE.value |
        LayoutParams.FLAG_NOT_TOUCH_MODAL.value,
      1,
    );
    params.gravity.value = Gravity.TOP.value | Gravity.START.value;

    this.logView = logText;
    this.windowRoot = root;
    this.windowParams = params;
    this.titleDragHandle = header;

    clearBtn.setOnClickListener(
      Java.registerClass({
        name: "LogClearClick" + Date.now() + Math.random().toString(36).slice(2),
        implements: [API.OnClickListener],
        methods: {
          onClick: () => {
            this._logRing = new Array(this._logMaxLinesCache || this.logMaxLines);
            this._logHead = 0;
            this._logSize = 0;
            this._logPending.length = 0;
            this.logView?.setText(JString.$new(""));
          },
        },
      }).$new(),
    );

    closeBtn.setOnClickListener(
      Java.registerClass({
        name: "LogCloseClick" + Date.now() + Math.random().toString(36).slice(2),
        implements: [API.OnClickListener],
        methods: {
          onClick: () => this.closeLogWindow(),
        },
      }).$new(),
    );

    this.bindDragForHeader();

    Java.scheduleOnMainThread(() => {
      try {
        this.windowManager.addView(this.windowRoot, this.windowParams);
        this.windowRoot.setVisibility(View.GONE.value);
        this.isCreated = true;
      } catch (e) {
        Logger.instance.error("create log window failed: " + e);
      }
    });

    this.bindLoggerToLogViewOnce();
  }

  private bindDragForHeader(): void {
    if (!this.titleDragHandle || !this.windowRoot || !this.windowParams) return;

    const MotionEvent = API.MotionEvent;
    let downRawX = 0;
    let downRawY = 0;
    let startX = 0;
    let startY = 0;

    this.titleDragHandle.setOnTouchListener(
      Java.registerClass({
        name: "LogHeaderDrag" + Date.now() + Math.random().toString(36).slice(2),
        implements: [API.OnTouchListener],
        methods: {
          onTouch: (_v: any, event: any) => {
            const action = event.getAction();
            if (action === MotionEvent.ACTION_DOWN.value) {
              downRawX = event.getRawX();
              downRawY = event.getRawY();
              startX = this.windowParams.x.value;
              startY = this.windowParams.y.value;
              return true;
            }

            if (action === MotionEvent.ACTION_MOVE.value) {
              const dx = event.getRawX() - downRawX;
              const dy = event.getRawY() - downRawY;
              this.windowParams.x.value = (startX + dx) | 0;
              this.windowParams.y.value = (startY + dy) | 0;

              Java.scheduleOnMainThread(() => {
                try {
                  this.windowManager.updateViewLayout(
                    this.windowRoot,
                    this.windowParams,
                  );
                } catch {}
              });
              return true;
            }
            return false;
          },
        },
      }).$new(),
    );
  }

  public openLogWindow(): void {
    this.createWindowOnce();
    if (!this.windowRoot) return;

    const View = API.View;
    this.isLogWindowVisible = true;
    Java.scheduleOnMainThread(() => {
      try {
        this.windowRoot.setVisibility(View.VISIBLE.value);
        this.windowRoot.bringToFront();
      } catch {}
    });
  }

  public closeLogWindow(): void {
    if (!this.windowRoot) return;

    const View = API.View;
    this.isLogWindowVisible = false;
    Java.scheduleOnMainThread(() => {
      try {
        this.windowRoot.setVisibility(View.GONE.value);
      } catch {}
    });
  }
}
