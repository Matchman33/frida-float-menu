"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.dp = dp;
exports.applyStyle = applyStyle;
exports.applyEditTextStyle = applyEditTextStyle;
const api_1 = require("../../api");
function dp(ctx, v) {
    const dm = ctx.getResources().getDisplayMetrics();
    return Math.floor(v * dm.density.value + 0.5);
}
function applyStyle(view, role, theme) {
    const ctx = view.getContext();
    const dpx = (v) => dp(ctx, v);
    const withAlpha = (color, alpha) => {
        const a = Math.max(0, Math.min(255, alpha)) & 0xff;
        return (a << 24) | (color & 0x00ffffff) | 0;
    };
    const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
    const TextView = Java.use("android.widget.TextView");
    const rounded = (bg, rDp, stroke) => {
        const d = GradientDrawable.$new();
        d.setColor(bg | 0);
        d.setCornerRadius(dp(ctx, rDp));
        if (stroke)
            d.setStroke(dp(ctx, stroke.wDp), stroke.c);
        view.setBackground(d);
    };
    const asTextView = () => {
        try {
            return Java.cast(view, TextView);
        }
        catch (_e) {
            return null;
        }
    };
    switch (role) {
        case "overlay":
            rounded(theme.colors.overlayBg, theme.radiusDp.overlay);
            view.setPadding(dp(ctx, 12), dp(ctx, 12), dp(ctx, 12), dp(ctx, 12));
            view.setElevation(dp(ctx, 10));
            break;
        case "card":
            rounded(theme.colors.cardBg, theme.radiusDp.card, {
                c: theme.colors.divider,
                wDp: 1,
            });
            view.setPadding(dp(ctx, 12), dp(ctx, 12), dp(ctx, 12), dp(ctx, 12));
            view.setElevation(dp(ctx, 6));
            break;
        case "category": {
            const bg = theme.colors.accentSoft ?? withAlpha(theme.colors.accent, 0x22);
            const stroke = theme.colors.accentStroke ?? theme.colors.controlStroke;
            rounded(bg, 1, { c: stroke, wDp: 2 });
            view.setPadding(dpx(14), dpx(10), dpx(14), dpx(10));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.text);
                tv.setTextSize(2, theme.textSp.title);
                tv.setTypeface(null, 1);
                tv.setGravity(api_1.API.Gravity.CENTER.value);
                try {
                    tv.setTypeface(null, 1);
                }
                catch (e) {
                }
            }
            break;
        }
        case "row": {
            const rowBg = theme.colors.rowBg ?? withAlpha(theme.colors.controlBg, 0x22);
            const stroke = withAlpha(theme.colors.controlStroke, 0x33);
            rounded(rowBg, theme.radiusDp.control, { c: stroke, wDp: 1 });
            view.setPadding(dpx(12), dpx(10), dpx(12), dpx(10));
            break;
        }
        case "text": {
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.text);
                tv.setTextSize(2, theme.textSp.body);
            }
            break;
        }
        case "caption": {
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.subText);
                tv.setTextSize(2, theme.textSp.caption);
            }
            break;
        }
        case "inputTrigger": {
            const bg = theme.colors.accentSoft ?? theme.colors.controlBg;
            const stroke = theme.colors.accentStroke ?? theme.colors.controlStroke;
            rounded(bg, theme.radiusDp.control, { c: stroke, wDp: 2 });
            view.setPadding(dpx(12), dpx(10), dpx(12), dpx(10));
            view.setMinimumHeight(dp(ctx, 42));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.text);
                tv.setTextSize(2, theme.textSp.body);
                tv.setAllCaps(false);
            }
            break;
        }
        case "primaryButton": {
            rounded(theme.colors.accent, theme.radiusDp.control);
            view.setPadding(dp(ctx, 14), dp(ctx, 10), dp(ctx, 14), dp(ctx, 10));
            view.setMinimumHeight(dp(ctx, 40));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(0xffffffff | 0);
                tv.setTextSize(2, theme.textSp.body);
                tv.setAllCaps(false);
            }
            break;
        }
        case "dangerButton": {
            rounded(theme.colors.danger, theme.radiusDp.control);
            view.setPadding(dp(ctx, 14), dp(ctx, 10), dp(ctx, 14), dp(ctx, 10));
            view.setMinimumHeight(dp(ctx, 40));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(0xffffffff | 0);
                tv.setTextSize(2, theme.textSp.body);
                tv.setAllCaps(false);
            }
            break;
        }
        case "headerBar": {
            const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
            const ctx = view.getContext();
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dp(ctx, 14));
            bg.setColor(theme.colors.cardBg);
            bg.setStroke(dp(ctx, 1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dp(ctx, 10), dp(ctx, 8), dp(ctx, 10), dp(ctx, 8));
            break;
        }
        case "iconButton": {
            const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
            const ctx = view.getContext();
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dp(ctx, 10));
            bg.setColor(0x00000000);
            bg.setStroke(dp(ctx, 1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dp(ctx, 6), dp(ctx, 6), dp(ctx, 6), dp(ctx, 6));
            if (view.setAllCaps)
                view.setAllCaps(false);
            if (view.setTextColor)
                view.setTextColor(theme.colors.text);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            break;
        }
        case "textButton": {
            const ctx = view.getContext();
            try {
                view.setBackground(null);
            }
            catch (e) { }
            if (view.setAllCaps)
                view.setAllCaps(false);
            if (view.setTextColor)
                view.setTextColor(theme.colors.accent);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            view.setPadding(dp(ctx, 8), dp(ctx, 6), dp(ctx, 8), dp(ctx, 6));
            break;
        }
        case "dangerTextButton": {
            const ctx = view.getContext();
            try {
                view.setBackground(null);
            }
            catch (e) { }
            if (view.setAllCaps)
                view.setAllCaps(false);
            if (view.setTextColor)
                view.setTextColor(theme.colors.danger ?? theme.colors.accent);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            view.setPadding(dp(ctx, 8), dp(ctx, 6), dp(ctx, 8), dp(ctx, 6));
            break;
        }
        case "divider": {
            const ctx = view.getContext();
            view.setBackgroundColor(theme.colors.divider);
            const lp = view.getLayoutParams?.();
            if (lp) {
                lp.height = dp(ctx, 1);
                view.setLayoutParams(lp);
            }
            break;
        }
        case "chip": {
            const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
            const ctx = view.getContext();
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dp(ctx, 999));
            bg.setColor(theme.colors.chipBg ?? theme.colors.rowBg);
            bg.setStroke(dp(ctx, 1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dp(ctx, 10), dp(ctx, 4), dp(ctx, 10), dp(ctx, 4));
            if (view.setTextColor)
                view.setTextColor(theme.colors.subText);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.caption ?? theme.textSp.body);
            break;
        }
        case "dialog": {
            const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
            const ctx = view.getContext();
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dp(ctx, 14));
            bg.setColor(theme.colors.cardBg);
            bg.setStroke(dp(ctx, 1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dp(ctx, 12), dp(ctx, 12), dp(ctx, 12), dp(ctx, 12));
            break;
        }
        case "inputField": {
            const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
            const ctx = view.getContext();
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dp(ctx, 12));
            bg.setColor(theme.colors.inputBg ?? theme.colors.rowBg);
            bg.setStroke(dp(ctx, 1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));
            if (view.setTextColor)
                view.setTextColor(theme.colors.text);
            if (view.setHintTextColor)
                view.setHintTextColor(theme.colors.subText);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            break;
        }
    }
}
function applyEditTextStyle(editText, theme) {
    const ctx = editText.getContext();
    const GradientDrawable = Java.use("android.graphics.drawable.GradientDrawable");
    const d = GradientDrawable.$new();
    d.setColor(theme.colors.controlBg);
    d.setCornerRadius(dp(ctx, theme.radiusDp.control));
    d.setStroke(dp(ctx, 1), theme.colors.controlStroke);
    editText.setBackground(d);
    editText.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));
    try {
        editText.setTextColor(theme.colors.text);
        editText.setHintTextColor(theme.colors.subText);
        if (editText.setHighlightColor)
            editText.setHighlightColor(theme.colors.accent);
        if (editText.setLinkTextColor)
            editText.setLinkTextColor(theme.colors.accent);
    }
    catch (_e) { }
}
