import { Theme } from "./theme";

export type StyleRole =
  | "overlay"
  | "card"
  | "category" // section header
  | "row" // settings row container
  | "text"
  | "caption"
  | "inputTrigger" // looks like an input field but clickable
  | "primaryButton"
  | "dangerButton";

export function dp(ctx: any, v: number): number {
  const dm = ctx.getResources().getDisplayMetrics();
  return Math.floor(v * dm.density.value + 0.5);
}

export function applyStyle(view: any, role: StyleRole, theme: Theme) {
  const ctx = view.getContext();
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
      rounded(theme.colors.controlBg, theme.radiusDp.control, {
        c: theme.colors.divider,
        wDp: 1,
      });
      view.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));
      const tv = asTextView();
      if (tv) {
        tv.setTextColor(theme.colors.text);
        tv.setTextSize(2, theme.textSp.title);
        tv.setTypeface(null, 1);
      }
      break;
    }

    case "row": {
      rounded(theme.colors.controlBg, theme.radiusDp.control, {
        c: theme.colors.divider,
        wDp: 1,
      });
      view.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));
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
      rounded(theme.colors.controlBg, theme.radiusDp.control, {
        c: theme.colors.controlStroke,
        wDp: 1,
      });
      view.setPadding(dp(ctx, 12), dp(ctx, 10), dp(ctx, 12), dp(ctx, 10));
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
