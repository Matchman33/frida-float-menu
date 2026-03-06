import { API } from "../../api";
import { Theme } from "./theme";

export type StyleRole =
  | "overlay"
  | "card"
  | "category"
  | "row"
  | "text"
  | "caption"
  | "inputTrigger"
  | "primaryButton"
  | "dangerButton"
  // ✅ 新增
  | "headerBar" // 顶部标题栏容器（更紧凑、更像面板头）
  | "iconButton" // 标题栏小按钮：方形/圆角/描边/透明底
  | "textButton" // 弹窗/列表里的“文字按钮”
  | "dangerTextButton" // 红色文字按钮（例如 删除/清空）
  | "divider" // 分割线 View
  | "chip" // 小标签/状态胶囊（可选）
  | "dialog" // Dialog 内容容器背景（圆角+描边）
  | "inputField"; // EditText / 输入框（和 trigger 区分）
export function dp(ctx: any, v: number): number {
  const dm = ctx.getResources().getDisplayMetrics();
  return Math.floor(v * dm.density.value + 0.5);
}

export function applyStyle(view: any, role: StyleRole, theme: Theme) {
  const ctx = view.getContext();

  // dp 简写
  const dpx = (v: number) => dp(ctx, v);

  // color helper: 0xAARRGGBB
  const withAlpha = (color: number, alpha: number) => {
    const a = Math.max(0, Math.min(255, alpha)) & 0xff;
    return (a << 24) | (color & 0x00ffffff) | 0;
  };
  const GradientDrawable = Java.use(
    "android.graphics.drawable.GradientDrawable",
  );
  const TextView = Java.use("android.widget.TextView");

  const rounded = (
    bg: number,
    rDp: number,
    stroke?: { c: number; wDp: number },
  ) => {
    const d = GradientDrawable.$new();
    d.setColor(bg | 0);
    d.setCornerRadius(dp(ctx, rDp));
    if (stroke) d.setStroke(dp(ctx, stroke.wDp), stroke.c);
    view.setBackground(d);
  };

  const asTextView = () => {
    try {
      return Java.cast(view, TextView);
    } catch (_e) {
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
      // 分组标题：用 accentSoft + 更明显描边，和 row / input 区分开
      const bg =
        theme.colors.accentSoft ?? withAlpha(theme.colors.accent, 0x22);
      const stroke = theme.colors.accentStroke ?? theme.colors.controlStroke;
      rounded(bg, 1, { c: stroke, wDp: 2 });
      view.setPadding(dpx(14), dpx(10), dpx(14), dpx(10));
      const tv = asTextView();
      if (tv) {
        tv.setTextColor(theme.colors.text);
        tv.setTextSize(2, theme.textSp.title);
        tv.setTypeface(null, 1);
        tv.setGravity(API.Gravity.CENTER.value);
        // ✅ 加粗（等价于 Typeface.BOLD）
        try {
          tv.setTypeface(null, 1); // 1 = Typeface.BOLD
        } catch (e) {
          // 有些 ROM/桥接下 setTypeface 可能不稳定，忽略即可
        }
      }
      break;
    }

    case "row": {
      // row：弱交互的“承载块”，不要和 input / trigger 同质化
      const rowBg =
        theme.colors.rowBg ?? withAlpha(theme.colors.controlBg, 0x22);
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
      // 看起来像“可点击的输入框/选择器”，和 inputField / row 区分
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
      // 用于悬浮窗顶部标题栏
      const GradientDrawable = Java.use(
        "android.graphics.drawable.GradientDrawable",
      );
      const ctx = view.getContext();

      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(ctx, 14));
      bg.setColor(theme.colors.cardBg);
      bg.setStroke(
        dp(ctx, 1),
        theme.colors.accentStroke ?? theme.colors.controlStroke,
      );

      view.setBackgroundDrawable(bg);
      view.setPadding(dp(ctx, 10), dp(ctx, 8), dp(ctx, 10), dp(ctx, 8));
      break;
    }

    case "iconButton": {
      // 小方块按钮，适合 “— / × / ⚙ / 隐藏”
      const GradientDrawable = Java.use(
        "android.graphics.drawable.GradientDrawable",
      );
      const ctx = view.getContext();

      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(ctx, 10));
      bg.setColor(0x00000000); // 透明
      bg.setStroke(
        dp(ctx, 1),
        theme.colors.accentStroke ?? theme.colors.controlStroke,
      );

      view.setBackgroundDrawable(bg);
      view.setPadding(dp(ctx, 6), dp(ctx, 6), dp(ctx, 6), dp(ctx, 6));

      // 如果是 TextView/Button 之类
      if (view.setAllCaps) view.setAllCaps(false);
      if (view.setTextColor) view.setTextColor(theme.colors.text);
      if (view.setTextSize) view.setTextSize(2, theme.textSp.body);
      break;
    }

    case "textButton": {
      // 纯文字按钮：无背景，accent 色
      const ctx = view.getContext();
      try {
        view.setBackground(null);
      } catch (e) {}

      if (view.setAllCaps) view.setAllCaps(false);
      if (view.setTextColor) view.setTextColor(theme.colors.accent);
      if (view.setTextSize) view.setTextSize(2, theme.textSp.body);
      view.setPadding(dp(ctx, 8), dp(ctx, 6), dp(ctx, 8), dp(ctx, 6));
      break;
    }

    case "dangerTextButton": {
      const ctx = view.getContext();
      try {
        view.setBackground(null);
      } catch (e) {}

      if (view.setAllCaps) view.setAllCaps(false);
      if (view.setTextColor)
        view.setTextColor(theme.colors.danger ?? theme.colors.accent);
      if (view.setTextSize) view.setTextSize(2, theme.textSp.body);
      view.setPadding(dp(ctx, 8), dp(ctx, 6), dp(ctx, 8), dp(ctx, 6));
      break;
    }

    case "divider": {
      // 一个简单分割线 view（高度 1dp）
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
      // 小胶囊（比如“已启用 / 3项已选”）
      const GradientDrawable = Java.use(
        "android.graphics.drawable.GradientDrawable",
      );
      const ctx = view.getContext();

      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(ctx, 999)); // 胶囊
      bg.setColor(theme.colors.chipBg ?? theme.colors.rowBg);
      bg.setStroke(
        dp(ctx, 1),
        theme.colors.accentStroke ?? theme.colors.controlStroke,
      );

      view.setBackgroundDrawable(bg);
      view.setPadding(dp(ctx, 10), dp(ctx, 4), dp(ctx, 10), dp(ctx, 4));

      if (view.setTextColor) view.setTextColor(theme.colors.subText);
      if (view.setTextSize)
        view.setTextSize(2, theme.textSp.caption ?? theme.textSp.body);
      break;
    }

    case "dialog": {
      // 给 dialog 的 decor / container 用：圆角暗底 + 描边
      const GradientDrawable = Java.use(
        "android.graphics.drawable.GradientDrawable",
      );
      const ctx = view.getContext();

      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(ctx, 14));
      bg.setColor(theme.colors.cardBg);
      bg.setStroke(
        dp(ctx, 1),
        theme.colors.accentStroke ?? theme.colors.controlStroke,
      );

      view.setBackgroundDrawable(bg);
      view.setPadding(dp(ctx, 12), dp(ctx, 12), dp(ctx, 12), dp(ctx, 12));
      break;
    }

    case "inputField": {
      // 真正的 EditText 输入框（比 inputTrigger 更“可编辑”）
      const GradientDrawable = Java.use(
        "android.graphics.drawable.GradientDrawable",
      );
      const ctx = view.getContext();

      const bg = GradientDrawable.$new();
      bg.setCornerRadius(dp(ctx, 12));
      bg.setColor(theme.colors.inputBg ?? theme.colors.rowBg);
      bg.setStroke(
        dp(ctx, 1),
        theme.colors.accentStroke ?? theme.colors.controlStroke,
      );

      view.setBackgroundDrawable(bg);
      view.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));

      if (view.setTextColor) view.setTextColor(theme.colors.text);
      if (view.setHintTextColor) view.setHintTextColor(theme.colors.subText);
      if (view.setTextSize) view.setTextSize(2, theme.textSp.body);
      break;
    }
  }
}

export function applyEditTextStyle(editText: any, theme: Theme) {
  const ctx = editText.getContext();
  const GradientDrawable = Java.use(
    "android.graphics.drawable.GradientDrawable",
  );

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
  } catch (_e) {}
}
