import { API } from "../../api";
import { Logger } from "../../logger";
import { dp } from "../style/style";
export class LogView {
    constructor(context, height, theme, logMaxLines = 100) {
        this.isLogDrawerOpen = false;
        this._logMaxLinesCache = 0;
        this._logRing = null;
        this._logHead = 0;
        this._logSize = 0;
        this._logPending = [];
        this._logFlushScheduled = false;
        this.context = context;
        this.height = height;
        this.logMaxLines = logMaxLines;
        this.theme = theme;
    }
    bindLoggerToLogViewOnce() {
        if (this._loggerUnsub)
            return;
        const self = this;
        this._loggerUnsub = Logger.instance.onLog((items) => {
            for (let i = 0; i < items.length; i++) {
                const it = items[i];
                self.addLogToView(it.level, it.message, it.ts);
            }
        }, true);
    }
    addLogToView(level, message, ts) {
        if (!this.logView)
            return;
        const maxLines = this.logMaxLines | 0;
        if (maxLines <= 0)
            return;
        if (!this._logRing || this._logMaxLinesCache !== maxLines) {
            this._logMaxLinesCache = maxLines;
            this._logRing = new Array(maxLines);
            this._logHead = 0;
            this._logSize = 0;
            this._logPending.length = 0;
            this._logFlushScheduled = false;
            this.logView.setText(API.JString.$new(""));
        }
        this._logPending.push(`[${level.toUpperCase()} ${new Date(ts).toTimeString().substring(0, 8)}] ${message}`);
        if (this._logFlushScheduled)
            return;
        this._logFlushScheduled = true;
        Java.scheduleOnMainThread(() => {
            this._logFlushScheduled = false;
            if (!this.logView || !this._logRing)
                return;
            while (this._logPending.length > 0) {
                const line = this._logPending.shift();
                this._logRing[this._logHead] = line;
                this._logHead = (this._logHead + 1) % this._logMaxLinesCache;
                if (this._logSize < this._logMaxLinesCache)
                    this._logSize++;
            }
            let out = "";
            const start = (this._logHead - this._logSize + this._logMaxLinesCache) %
                this._logMaxLinesCache;
            for (let i = 0; i < this._logSize; i++) {
                const idx = (start + i) % this._logMaxLinesCache;
                const s = this._logRing[idx];
                if (s == null)
                    continue;
                out += s;
                if (i !== this._logSize - 1)
                    out += "\n";
            }
            this.logView.setText(API.JString.$new(out));
        });
    }
    createViewOnce(parentView) {
        if (!parentView) {
            Logger.instance.error("LogView: parentView is null");
            return;
        }
        this.parentView = parentView;
        if (this.logDrawerPanel)
            return;
        const LinearLayout = API.LinearLayout;
        const FrameLayoutParams = API.FrameLayoutParams;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const Gravity = API.Gravity;
        const GradientDrawable = API.GradientDrawable;
        const ctx = this.context;
        try {
            this.parentView.setClipChildren(false);
        }
        catch { }
        try {
            this.parentView.setClipToPadding(false);
        }
        catch { }
        const panel = LinearLayout.$new(this.context);
        panel.setOrientation(LinearLayout.VERTICAL.value);
        const panelLp = FrameLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, this.height);
        panelLp.gravity.value = Gravity.BOTTOM.value;
        panel.setLayoutParams(panelLp);
        panel.setAlpha(0.9);
        const bg = GradientDrawable.$new();
        bg.setCornerRadius(dp(ctx, 14));
        bg.setColor(this.theme.colors.cardBg);
        bg.setStroke(dp(ctx, 1), this.theme.colors.divider);
        panel.setBackgroundDrawable(bg);
        panel.setPadding(dp(ctx, 8), dp(ctx, 8), dp(ctx, 8), dp(ctx, 8));
        try {
            panel.setTranslationY(this.height);
        }
        catch { }
        try {
            panel.setElevation(100001);
        }
        catch { }
        try {
            panel.setTranslationZ(100001);
        }
        catch { }
        const logRoot = this.createLogView();
        logRoot.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.MATCH_PARENT.value));
        this.logScrollView = logRoot;
        panel.addView(logRoot);
        this.bindLoggerToLogViewOnce();
        Java.scheduleOnMainThread(() => {
            try {
                this.parentView.addView(panel);
                try {
                    panel.bringToFront();
                }
                catch { }
            }
            catch (e) {
                Logger.instance.error("ensureLogDrawer failed: " + e);
            }
        });
        this.logDrawerPanel = panel;
    }
    openLogDrawer() {
        if (!this.logDrawerPanel)
            return;
        const View = API.View;
        this.isLogDrawerOpen = true;
        Java.scheduleOnMainThread(() => {
            try {
                this.logDrawerPanel.setVisibility(View.VISIBLE.value);
                try {
                    this.logDrawerPanel.bringToFront();
                }
                catch { }
                try {
                    this.logDrawerPanel.animate()
                        .translationY(0)
                        .setDuration(180)
                        .start();
                }
                catch {
                    this.logDrawerPanel.setTranslationY(0);
                }
            }
            catch { }
        });
    }
    closeLogDrawer() {
        const View = API.View;
        this.isLogDrawerOpen = false;
        const endAction = Java.registerClass({
            name: "LogBottomCloseEnd" +
                Date.now() +
                Math.random().toString(36).substring(4),
            implements: [Java.use("java.lang.Runnable")],
            methods: {
                run: () => {
                    try {
                        this.logDrawerPanel.setVisibility(View.GONE.value);
                    }
                    catch { }
                },
            },
        }).$new();
        Java.scheduleOnMainThread(() => {
            try {
                try {
                    this.logDrawerPanel.animate()
                        .translationY(this.height)
                        .setDuration(160)
                        .withEndAction(endAction)
                        .start();
                }
                catch {
                    this.logDrawerPanel.setTranslationY(this.height);
                    this.logDrawerPanel.setVisibility(View.GONE.value);
                }
            }
            catch { }
        });
    }
    createLogView() {
        const ScrollView = API.ScrollView;
        const TextView = API.TextView;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const LinearLayoutParams = API.LinearLayoutParams;
        const JString = API.JString;
        const Gravity = API.Gravity;
        const sv = ScrollView.$new(this.context);
        sv.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.MATCH_PARENT.value));
        try {
            sv.setFillViewport(true);
            sv.setVerticalScrollBarEnabled(false);
            sv.setBackgroundColor(0x00000000);
        }
        catch (e) {
            Logger.instance.error("createLogView setFillViewport failed: " + e);
        }
        const tv = TextView.$new(this.context);
        tv.setLayoutParams(ViewGroupLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        tv.setTextColor(this.theme.colors.text);
        tv.setTextSize(2, this.theme.textSp.body);
        tv.setGravity(Gravity.START.value);
        tv.setIncludeFontPadding(false);
        tv.setPadding(dp(this.context, 10), dp(this.context, 8), dp(this.context, 10), dp(this.context, 8));
        tv.setText(JString.$new(""));
        sv.addView(tv);
        this.logView = tv;
        return sv;
    }
}
