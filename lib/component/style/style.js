import Java from "frida-java-bridge";
import { API } from "../../api.js";
export function dp(ctx, v) {
    const dm = ctx.getResources().getDisplayMetrics();
    return Math.floor(v * dm.density.value + 0.5);
}
export function applyStyle(view, role, theme) {
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
        case "overlay": {
            const bg = GradientDrawable.$new();
            bg.setShape(GradientDrawable.RECTANGLE.value);
            bg.setCornerRadius(dpx(theme.radiusDp.overlay));
            bg.setColor(theme.colors.overlayBg | 0);
            bg.setStroke(dpx(1), (theme.colors.accentStroke ?? theme.colors.controlStroke) | 0);
            view.setBackgroundDrawable(bg);
            view.setPadding(dpx(12), dpx(12), dpx(12), dpx(12));
            try {
                view.setElevation(dpx(12));
            }
            catch (_e) { }
            break;
        }
        case "card":
            rounded(theme.colors.cardBg, theme.radiusDp.card, {
                c: theme.colors.divider,
                wDp: 1,
            });
            view.setPadding(dpx(12), dpx(12), dpx(12), dpx(12));
            view.setElevation(dpx(6));
            break;
        case "infoCard":
            rounded(theme.colors.infoCardBg ?? withAlpha(theme.colors.cardBg, 0xdd), 12, {
                c: withAlpha(theme.colors.accentStroke ?? theme.colors.controlStroke, 0x55),
                wDp: 1,
            });
            view.setPadding(dpx(14), dpx(12), dpx(14), dpx(12));
            break;
        case "inputButton": {
            const bg = theme.colors.rowBg ?? withAlpha(theme.colors.controlBg, 0x26);
            const stroke = theme.colors.accentStroke ?? theme.colors.controlStroke;
            rounded(bg, 14, { c: withAlpha(stroke, 0xaa), wDp: 1 });
            view.setPadding(dpx(14), dpx(12), dpx(14), dpx(12));
            view.setMinimumHeight(dp(ctx, 48));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.text);
                tv.setTextSize(2, 14);
                tv.setAllCaps(false);
                tv.setGravity(API.Gravity.LEFT.value | API.Gravity.CENTER_VERTICAL.value);
                try {
                    tv.setTypeface(null, 1);
                }
                catch (_e) { }
            }
            break;
        }
        case "noteCard":
            rounded(theme.colors.noteCardBg ?? withAlpha(theme.colors.accent, 0x18), 12, {
                c: theme.colors.accentStroke ?? theme.colors.controlStroke,
                wDp: 1,
            });
            view.setPadding(dpx(14), dpx(12), dpx(14), dpx(12));
            break;
        case "fieldLabel": {
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.subText);
                tv.setTextSize(2, 11);
                tv.setAllCaps(true);
                try {
                    tv.setTypeface(null, 1);
                }
                catch (_e) { }
                try {
                    tv.setLetterSpacing(0.04);
                }
                catch (_e) { }
            }
            break;
        }
        case "selectValue": {
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.text);
                tv.setTextSize(2, 14);
                try {
                    tv.setTypeface(null, 1);
                }
                catch (_e) { }
                tv.setSingleLine(true);
                tv.setGravity(API.Gravity.LEFT.value | API.Gravity.CENTER_VERTICAL.value);
            }
            break;
        }
        case "category": {
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.sectionText ?? theme.colors.subText);
                tv.setTextSize(2, 14);
                tv.setAllCaps(true);
                try {
                    tv.setLetterSpacing(0.06);
                }
                catch (_e) { }
                try {
                    tv.setTypeface(null, 1);
                }
                catch (_e) { }
                tv.setGravity(API.Gravity.LEFT.value | API.Gravity.CENTER_VERTICAL.value);
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
                tv.setTextColor(0xffd8e1f0 | 0);
                tv.setTextSize(2, 13);
                tv.setGravity(API.Gravity.LEFT.value);
                try {
                    tv.setLineSpacing(dpx(4), 1.0);
                }
                catch (_e) { }
            }
            break;
        }
        case "noteText": {
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(0xffc9d4e8 | 0);
                tv.setTextSize(2, 13);
                tv.setGravity(API.Gravity.LEFT.value);
                try {
                    tv.setLineSpacing(dpx(4), 1.0);
                }
                catch (_e) { }
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
            view.setMinimumHeight(dpx(42));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.text);
                tv.setTextSize(2, theme.textSp.body);
                tv.setAllCaps(false);
            }
            break;
        }
        case "primaryButton": {
            rounded(theme.colors.accent, 14);
            view.setPadding(dpx(16), dpx(12), dpx(16), dpx(12));
            view.setMinimumHeight(dpx(48));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.buttonText ?? 0xffffffff | 0);
                tv.setTextSize(2, 14);
                tv.setAllCaps(true);
                try {
                    tv.setTypeface(null, 1);
                }
                catch (_e) { }
                tv.setGravity(API.Gravity.CENTER.value);
            }
            break;
        }
        case "dangerButton": {
            rounded(theme.colors.danger, 14);
            view.setPadding(dpx(16), dpx(12), dpx(16), dpx(12));
            view.setMinimumHeight(dpx(48));
            const tv = asTextView();
            if (tv) {
                tv.setTextColor(theme.colors.buttonText ?? 0xffffffff | 0);
                tv.setTextSize(2, 14);
                tv.setAllCaps(true);
                try {
                    tv.setTypeface(null, 1);
                }
                catch (_e) { }
                tv.setGravity(API.Gravity.CENTER.value);
            }
            break;
        }
        case "headerBar": {
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dpx(14));
            bg.setColor(theme.colors.cardBg);
            bg.setStroke(dpx(1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dpx(10), dpx(8), dpx(10), dpx(8));
            break;
        }
        case "iconButton": {
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dpx(10));
            bg.setColor(0x00000000);
            bg.setStroke(dpx(1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dpx(6), dpx(6), dpx(6), dpx(6));
            if (view.setAllCaps)
                view.setAllCaps(false);
            if (view.setTextColor)
                view.setTextColor(theme.colors.text);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            break;
        }
        case "textButton": {
            try {
                view.setBackground(null);
            }
            catch (_e) { }
            if (view.setAllCaps)
                view.setAllCaps(false);
            if (view.setTextColor)
                view.setTextColor(theme.colors.accent);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            view.setPadding(dpx(8), dpx(6), dpx(8), dpx(6));
            break;
        }
        case "dangerTextButton": {
            try {
                view.setBackground(null);
            }
            catch (_e) { }
            if (view.setAllCaps)
                view.setAllCaps(false);
            if (view.setTextColor)
                view.setTextColor(theme.colors.danger ?? theme.colors.accent);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            view.setPadding(dpx(8), dpx(6), dpx(8), dpx(6));
            break;
        }
        case "divider": {
            view.setBackgroundColor(theme.colors.divider);
            const lp = view.getLayoutParams?.();
            if (lp) {
                lp.height = dpx(1);
                view.setLayoutParams(lp);
            }
            break;
        }
        case "chip": {
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dpx(999));
            bg.setColor(theme.colors.chipBg ?? theme.colors.rowBg);
            bg.setStroke(dpx(1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dpx(10), dpx(4), dpx(10), dpx(4));
            if (view.setTextColor)
                view.setTextColor(theme.colors.subText);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.caption ?? theme.textSp.body);
            break;
        }
        case "dialog": {
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dpx(14));
            bg.setColor(theme.colors.cardBg);
            bg.setStroke(dpx(1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dpx(12), dpx(12), dpx(12), dpx(12));
            break;
        }
        case "inputField": {
            const bg = GradientDrawable.$new();
            bg.setCornerRadius(dpx(theme.radiusDp.control));
            bg.setColor(theme.colors.inputBg ?? theme.colors.controlBg);
            bg.setStroke(dpx(1), theme.colors.accentStroke ?? theme.colors.controlStroke);
            view.setBackgroundDrawable(bg);
            view.setPadding(dpx(12), dpx(10), dpx(12), dpx(10));
            if (view.setTextColor)
                view.setTextColor(theme.colors.text);
            if (view.setHintTextColor)
                view.setHintTextColor(theme.colors.subText ?? 0xff888888);
            if (view.setTextSize)
                view.setTextSize(2, theme.textSp.body);
            break;
        }
    }
}
