import { API } from "../../api";
import { Logger } from "../../logger";
import { dp } from "../style/style";
import { LogViewWindow } from "./log-view";
export class HeaderView {
    constructor(theme) {
        this.theme = theme;
    }
    createView(options, callbacks) {
        const { context, parent, logMaxLines, title, version, } = options;
        try {
            const LinearLayout = API.LinearLayout;
            const LinearLayoutParams = API.LinearLayoutParams;
            const TextView = API.TextView;
            const JString = API.JString;
            const GradientDrawable = API.GradientDrawable;
            const Gravity = API.Gravity;
            const PAD_H = dp(context, 10);
            const PAD_V = dp(context, 8);
            const BTN_SIZE = dp(context, 34);
            const BTN_RADIUS = dp(context, 10);
            const createIconCharBtn = (ch, isDanger = false) => {
                const btn = TextView.$new(context);
                btn.setText(JString.$new(ch));
                btn.setGravity(Gravity.CENTER.value);
                btn.setSingleLine(true);
                btn.setTextSize(2, this.theme.textSp.title);
                btn.setTextColor(isDanger ? this.theme.colors.accent : this.theme.colors.text);
                const lp = LinearLayoutParams.$new(BTN_SIZE, BTN_SIZE);
                btn.setLayoutParams(lp);
                btn.setOnTouchListener(Java.registerClass({
                    name: "HeaderBtnTouch_" +
                        Date.now() +
                        Math.random().toString(36).slice(2),
                    implements: [Java.use("android.view.View$OnTouchListener")],
                    methods: {
                        onTouch: function (v, ev) {
                            try {
                                const MotionEvent = Java.use("android.view.MotionEvent");
                                const action = ev.getAction();
                                if (action === MotionEvent.ACTION_DOWN.value)
                                    v.setAlpha(0.6);
                                else if (action === MotionEvent.ACTION_UP.value ||
                                    action === MotionEvent.ACTION_CANCEL.value) {
                                    v.setAlpha(1.0);
                                }
                            }
                            catch { }
                            return false;
                        },
                    },
                }).$new());
                const d = GradientDrawable.$new();
                d.setCornerRadius(BTN_RADIUS);
                d.setColor(0x00000000);
                btn.setBackgroundDrawable(d);
                btn.setPadding(dp(context, 6), dp(context, 6), dp(context, 6), dp(context, 6));
                return btn;
            };
            const headerLp = LinearLayoutParams.$new(LinearLayoutParams.MATCH_PARENT.value, LinearLayoutParams.WRAP_CONTENT.value);
            const headerRoot = LinearLayout.$new(context);
            headerRoot.setOrientation(1);
            headerRoot.setLayoutParams(headerLp);
            const headerRow = LinearLayout.$new(context);
            headerRow.setOrientation(0);
            headerRow.setGravity(Gravity.CENTER_VERTICAL.value);
            headerRow.setPadding(PAD_H, PAD_V, PAD_H, PAD_V);
            this.headerDragView = headerRow;
            try {
                this.headerDragView.setBackgroundColor(0x00000000);
            }
            catch { }
            const divider = API.View.$new(context);
            const divLp = LinearLayoutParams.$new(LinearLayoutParams.MATCH_PARENT.value, dp(context, 1));
            divider.setLayoutParams(divLp);
            divider.setBackgroundColor(this.theme.colors.divider);
            const leftBox = LinearLayout.$new(context);
            leftBox.setOrientation(0);
            leftBox.setGravity(Gravity.CENTER_VERTICAL.value);
            const leftLp = LinearLayoutParams.$new(0, LinearLayoutParams.WRAP_CONTENT.value, 1.0);
            leftBox.setLayoutParams(leftLp);
            const icon = TextView.$new(context);
            icon.setText(JString.$new("▸"));
            icon.setTextColor(this.theme.colors.accent);
            icon.setTextSize(2, this.theme.textSp.title);
            icon.setPadding(0, 0, dp(context, 8), 0);
            const titleView = TextView.$new(context);
            titleView.setText(JString.$new(title));
            titleView.setSingleLine(true);
            titleView.setTypeface(null, 1);
            titleView.setTextColor(this.theme.colors.text);
            titleView.setTextSize(2, this.theme.textSp.title);
            const ver = TextView.$new(context);
            ver.setText(JString.$new(version));
            ver.setSingleLine(true);
            ver.setTextSize(2, this.theme.textSp.caption);
            ver.setTextColor(this.theme.colors.accent);
            const badgeBg = GradientDrawable.$new();
            badgeBg.setCornerRadius(dp(context, 8));
            badgeBg.setColor(0x22000000);
            badgeBg.setStroke(dp(context, 1), this.theme.colors.divider);
            ver.setBackgroundDrawable(badgeBg);
            ver.setPadding(dp(context, 8), dp(context, 4), dp(context, 8), dp(context, 4));
            const verLp = LinearLayoutParams.$new(LinearLayoutParams.WRAP_CONTENT.value, LinearLayoutParams.WRAP_CONTENT.value);
            verLp.setMargins(dp(context, 10), 0, 0, 0);
            ver.setLayoutParams(verLp);
            leftBox.addView(icon);
            leftBox.addView(titleView);
            leftBox.addView(ver);
            const rightBox = LinearLayout.$new(context);
            rightBox.setOrientation(0);
            rightBox.setGravity(Gravity.CENTER_VERTICAL.value);
            const rightLp = LinearLayoutParams.$new(LinearLayoutParams.WRAP_CONTENT.value, LinearLayoutParams.WRAP_CONTENT.value);
            rightBox.setLayoutParams(rightLp);
            const logView = new LogViewWindow(context, this.theme, logMaxLines);
            const logButton = createIconCharBtn("L", false);
            logButton.setOnClickListener(Java.registerClass({
                name: "LogButtonClickListener" + Date.now(),
                implements: [API.OnClickListener],
                methods: {
                    onClick: function () {
                        logView.createWindowOnce();
                        if (logView.isLogWindowVisible) {
                            logView.closeLogWindow();
                            logButton.setText(API.JString.$new("L"));
                        }
                        else {
                            logView.openLogWindow();
                            logButton.setText(API.JString.$new("←"));
                        }
                    },
                },
            }).$new());
            const minButton = createIconCharBtn("—", false);
            minButton.setOnClickListener(Java.registerClass({
                name: "MinButtonClickListener" + Date.now(),
                implements: [API.OnClickListener],
                methods: {
                    onClick: function () {
                        callbacks.onMinimize();
                    },
                },
            }).$new());
            const hideButton = createIconCharBtn("X", true);
            hideButton.setOnClickListener(Java.registerClass({
                name: "HideButtonClickListener" + Date.now(),
                implements: [API.OnClickListener],
                methods: {
                    onClick: function () {
                        callbacks.onHide();
                    },
                },
            }).$new());
            const lp1 = LinearLayoutParams.$new(BTN_SIZE, BTN_SIZE);
            lp1.setMargins(0, 0, dp(context, 4), 0);
            logButton.setLayoutParams(lp1);
            const lp2 = LinearLayoutParams.$new(BTN_SIZE, BTN_SIZE);
            lp2.setMargins(0, 0, dp(context, 4), 0);
            minButton.setLayoutParams(lp2);
            const lp3 = LinearLayoutParams.$new(BTN_SIZE, BTN_SIZE);
            lp3.setMargins(0, 0, 0, 0);
            hideButton.setLayoutParams(lp3);
            rightBox.addView(logButton);
            rightBox.addView(minButton);
            rightBox.addView(hideButton);
            headerRoot.addView(headerRow);
            headerRoot.addView(divider);
            headerRow.addView(leftBox);
            headerRow.addView(rightBox);
            parent.addView(headerRoot);
            return this.headerDragView;
        }
        catch (error) {
            Logger.instance.error("Failed to create header view: " + error);
            return null;
        }
    }
}
