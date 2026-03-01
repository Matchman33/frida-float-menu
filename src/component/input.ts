import { API } from "../api";
import { applyEditTextStyle, applyStyle, dp } from "./style/style";
import { DarkNeonTheme } from "./style/theme";
import { UIComponent } from "./ui-components";

export class NumberInput extends UIComponent {
  private text: string;
  private hint: string;
  private min: number | null;
  private max: number | null;
  private handler?: (value: number) => void;
  private title: string;

  /**
   *
   * @param id 组件唯一id
   * @param initialValue 初始值
   * @param min 限定最小值
   * @param max 限定最大值
   * @param text 按钮提示文本
   * @param hint 输入框提示文本
   */
  constructor(
    id: string,
    initialValue: number = 0,
    min: number | null = null,
    max: number | null = null,
    text: string = "单击输入数值",
    hint: string = "请输入数值",
    title: string = "请输入",
  ) {
    super(id);
    this.value = initialValue;
    this.text = text;
    this.hint = hint;
    this.min = min;
    this.max = max;
    this.title = title;
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Switch:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.view.setText(String.$new(`${this.text}: ${this.value}`));
    });
  }

  protected createView(context: any): void {
    const Button = API.Button;
    const String = API.JString;

    this.view = Button.$new(context);
    this.view.setText(String.$new(`${this.text}: ${this.value}`));
    applyStyle(this.view, "inputTrigger", DarkNeonTheme);
    const self = this;

    // 点击按钮弹窗
    this.view.setOnClickListener(
      Java.registerClass({
        name:
          "com.frida.NumberInputClick" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [API.OnClickListener],
        methods: {
          onClick: function (v: any) {
            self.showDialog(context);
          },
        },
      }).$new(),
    );
  }

  private showDialog(context: any): void {
    Java.scheduleOnMainThread(() => {
      const AlertDialogBuilder = API.AlertDialogBuilder;
      const EditText = API.EditText;
      const String = API.JString;
      const TextViewBufferType = API.TextViewBufferType;
      const InputType = API.InputType;
      const LayoutParams = API.LayoutParams;
      const LinearLayoutParams = API.LinearLayoutParams;
      const ViewGroupLayoutParams = API.ViewGroupLayoutParams;

      const builder = AlertDialogBuilder.$new(context);
      builder.setTitle(String.$new(this.title));

      // ---- Input
      const input = EditText.$new(context);
      applyEditTextStyle(input, DarkNeonTheme);
      input.setHint(String.$new(this.hint));
      input.setText(
        String.$new(this.value + ""),
        TextViewBufferType.NORMAL.value,
      );

      // 数字（可小数/符号）
      input.setInputType(
        InputType.TYPE_CLASS_NUMBER.value |
          InputType.TYPE_NUMBER_FLAG_DECIMAL.value |
          InputType.TYPE_NUMBER_FLAG_SIGNED.value,
      );

      const lp = LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      );
      input.setLayoutParams(lp);
      // 给输入框加容器 padding（更像设置面板）
      const LinearLayout = API.LinearLayout;
      const container = LinearLayout.$new(context);
      container.setPadding(
        dp(context, 16),
        dp(context, 10),
        dp(context, 16),
        dp(context, 6),
      );
      container.addView(input);
      builder.setView(container);

      const self = this;

      // ---- Buttons
      builder.setPositiveButton(
        String.$new("确认"),
        Java.registerClass({
          name:
            "com.frida.NumberInputOK" +
            Date.now() +
            Math.random().toString(36).substring(6),
          implements: [API.DialogInterfaceOnClickListener],
          methods: {
            onClick: function (_dialog: any, _which: number) {
              const text =
                Java.cast(
                  input.getText(),
                  Java.use("java.lang.CharSequence"),
                ).toString() + "";

              if (text === "") {
                self.value = 0;
              } else {
                const num = parseFloat(text);
                if (!isNaN(num)) self.value = num;
                else return;
              }

              self.applyConstraints();
              self.view.setText(String.$new(`${self.text}: ${self.value}`));
              self.emit("valueChanged", self.value);
              if (self.handler) self.handler(self.value);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("取消"), null);

      const dialog = builder.create();

      // ---- Overlay window type (avoid BadTokenException)
      const window = dialog.getWindow();
      const BuildVERSION = Java.use("android.os.Build$VERSION");
      if (window) {
        if (BuildVERSION.SDK_INT.value >= 26) {
          window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value);
        } else {
          window.setType(LayoutParams.TYPE_PHONE.value);
        }
      }

      dialog.show();

      // ---- Theme the dialog (background + buttons)
      try {
        const bg = API.GradientDrawable.$new();
        bg.setColor(DarkNeonTheme.colors.cardBg);
        bg.setCornerRadius(dp(context, 14));
        bg.setStroke(dp(context, 1), DarkNeonTheme.colors.divider);

        const win = dialog.getWindow();
        if (win) {
          const decor = win.getDecorView();
          decor.setBackground(bg);
          decor.setPadding(
            dp(context, 12),
            dp(context, 12),
            dp(context, 12),
            dp(context, 12),
          );
        }

        // Buttons color
        const AlertDialog = Java.use("android.app.AlertDialog");
        const ad = Java.cast(dialog, AlertDialog);
        const BUTTON_POSITIVE = -1;
        const BUTTON_NEGATIVE = -2;

        const pos = ad.getButton(BUTTON_POSITIVE);
        const neg = ad.getButton(BUTTON_NEGATIVE);

        if (pos) {
          pos.setAllCaps(false);
          pos.setTextColor(DarkNeonTheme.colors.accent);
          pos.setPadding(
            dp(context, 10),
            dp(context, 8),
            dp(context, 10),
            dp(context, 8),
          );
        }
        if (neg) {
          neg.setAllCaps(false);
          neg.setTextColor(DarkNeonTheme.colors.subText);
          neg.setPadding(
            dp(context, 10),
            dp(context, 8),
            dp(context, 10),
            dp(context, 8),
          );
        }
      } catch (e) {
        // ignore styling failures on some ROMs
      }
      // ✅ 标题文字主题化（有的系统能拿到 id，有的拿不到，拿不到也不影响）
      try {
        const titleId = context
          .getResources()
          .getIdentifier(
            Java.use("java.lang.String").$new("alertTitle"),
            Java.use("java.lang.String").$new("id"),
            Java.use("java.lang.String").$new("android"),
          );
        if (titleId && titleId !== 0) {
          const tv = dialog.findViewById(titleId);
          if (tv) {
            const TextView = Java.use("android.widget.TextView");
            const t = Java.cast(tv, TextView);
            t.setTextColor(DarkNeonTheme.colors.text);
            // t.setTextSize(2, DarkNeonTheme.textSp.title);
          }
        }
      } catch (e) {
        console.trace(e);
      }
    });
  }

  public setOnValueChange(handler: (value: number) => void) {
    this.handler = handler;
  }
  private applyConstraints(): void {
    let constrained = this.value as number;
    if (this.min !== null) constrained = Math.max(this.min, constrained);
    if (this.max !== null) constrained = Math.min(this.max, constrained);

    this.value = constrained;
  }

  // 以下为原有公共方法（稍作调整）

  public setHint(hint: string): void {
    this.hint = hint;
    // 提示文本只在对话框中使用，无需实时更新视图
  }

  public setConstraints(min: number | null, max: number | null): void {
    this.min = min;
    this.max = max;
    // 重新验证当前值
    this.applyConstraints();
  }

  public getNumber(): number {
    return this.value as number;
  }

  public setNumber(value: number): void {
    this.value = value;
    this.applyConstraints();
  }
}
export class TextInput extends UIComponent {
  private text: string;
  private hint: string;
  private handler?: (value: string) => void;
  private title: string;

  /**
   *
   * @param id 组件id，应该唯一
   * @param initialValue 初始值
   * @param text 按钮文本
   * @param hint
   */
  constructor(
    id: string,
    initialValue: string = "",
    text: string = "单击输入文本",
    hint: string = "请输入文本",
    title = "请输入",
  ) {
    super(id);
    this.text = text;
    this.hint = hint;
    this.value = initialValue;
    this.title = title;
  }
  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Switch:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.view.setText(String.$new(`${this.text}: ${this.value}`));
    });
  }
  protected createView(context: any): void {
    const Button = API.Button;
    const String = API.JString;

    this.view = Button.$new(context);
    applyStyle(this.view, "inputTrigger", DarkNeonTheme);
    this.view.setText(String.$new(`${this.text}: ${this.value}`));
    const self = this;

    // 点击按钮弹窗
    this.view.setOnClickListener(
      Java.registerClass({
        name:
          "com.frida.AlertTextInputClick" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [API.OnClickListener],
        methods: {
          onClick: function (v: any) {
            self.showDialog(context);
          },
        },
      }).$new(),
    );
  }

  protected emitValue(value: any) {
    this.emit("valueChanged", value);
  }

  public setOnValueChange(handler: (value: string) => void) {
    this.handler = handler;
  }

  private showDialog(context: any): void {
    Java.scheduleOnMainThread(() => {
      const AlertDialogBuilder = API.AlertDialogBuilder;
      const EditText = API.EditText;
      const String = API.JString;
      const TextViewBufferType = API.TextViewBufferType;
      const builder = AlertDialogBuilder.$new(context);
      const LinearLayoutParams = API.LinearLayoutParams;
      const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
      const input = EditText.$new(context);
      const LinearLayout = API.LinearLayout;
      applyEditTextStyle(input, DarkNeonTheme);
      input.setHint(String.$new(this.hint));
      input.setText(String.$new(this.value), TextViewBufferType.NORMAL.value);
      builder.setTitle(String.$new(this.title));

      const lp = LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      );
      input.setLayoutParams(lp);
      // 给输入框加容器 padding（更像设置面板）
      const container = LinearLayout.$new(context);
      container.setPadding(
        dp(context, 16),
        dp(context, 10),
        dp(context, 16),
        dp(context, 6),
      );
      container.addView(input);
      builder.setView(container);
      // builder.setView(input);

      const self = this;

      builder.setPositiveButton(
        String.$new("确认"),
        Java.registerClass({
          name:
            "com.frida.AlertTextInputOK" +
            Date.now() +
            Math.random().toString(36).substring(6),
          implements: [API.DialogInterfaceOnClickListener],
          methods: {
            onClick: function (dialog: any, which: number) {
              const text =
                Java.cast(
                  input.getText(),
                  Java.use("java.lang.CharSequence"),
                ).toString() + "";
              self.value = text;
              self.view.setText(String.$new(`${self.text}: ${self.value}`));
              self.emit("valueChanged", text);
              if (self.handler) self.handler(text);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("取消"), null);
      const LayoutParams = API.LayoutParams;
      const dialog = builder.create();

      // ✅ dialog 背景圆角 + 暗色（融入 DarkNeonTheme）

      const bg = API.GradientDrawable.$new();
      bg.setColor(DarkNeonTheme.colors.cardBg);
      bg.setCornerRadius(dp(context, 14));
      bg.setStroke(dp(context, 1), DarkNeonTheme.colors.divider);
      // 关键步骤：修改对话框窗口的类型
      const window = dialog.getWindow();
      const BuildVERSION = Java.use("android.os.Build$VERSION");
      if (window) {
        if (BuildVERSION.SDK_INT.value >= 26) {
          window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value);
        } else {
          window.setType(LayoutParams.TYPE_PHONE.value);
        }
        // 或者对于低版本：LayoutParams.TYPE_PHONE (2002)
      }
      dialog.show();
      try {
        const decor = dialog.getWindow().getDecorView();
        decor.setBackground(bg);
        // 让 dialog 四周留一点边距，像卡片浮在上面
        decor.setPadding(
          dp(context, 12),
          dp(context, 12),
          dp(context, 12),
          dp(context, 12),
        );
      } catch (e) {
        console.trace(e);
      }

      // ✅ 按钮主题化
      try {
        const AlertDialog = Java.use("android.app.AlertDialog");
        const ad = Java.cast(dialog, AlertDialog);

        const BUTTON_POSITIVE = -1; // AlertDialog.BUTTON_POSITIVE
        const BUTTON_NEGATIVE = -2; // AlertDialog.BUTTON_NEGATIVE

        const pos = ad.getButton(BUTTON_POSITIVE);
        const neg = ad.getButton(BUTTON_NEGATIVE);

        if (pos) {
          pos.setAllCaps(false);
          pos.setTextColor(DarkNeonTheme.colors.accent);
          pos.setPadding(
            dp(context, 10),
            dp(context, 8),
            dp(context, 10),
            dp(context, 8),
          );
        }
        if (neg) {
          neg.setAllCaps(false);
          neg.setTextColor(DarkNeonTheme.colors.subText);
          neg.setPadding(
            dp(context, 10),
            dp(context, 8),
            dp(context, 10),
            dp(context, 8),
          );
        }
      } catch (e) {
        console.trace(e);
      }
      // ✅ 标题文字主题化（有的系统能拿到 id，有的拿不到，拿不到也不影响）
      try {
        const titleId = context
          .getResources()
          .getIdentifier(
            Java.use("java.lang.String").$new("alertTitle"),
            Java.use("java.lang.String").$new("id"),
            Java.use("java.lang.String").$new("android"),
          );
        if (titleId && titleId !== 0) {
          const tv = dialog.findViewById(titleId);
          if (tv) {
            const TextView = Java.use("android.widget.TextView");
            const t = Java.cast(tv, TextView);
            t.setTextColor(DarkNeonTheme.colors.text);
            // t.setTextSize(2, DarkNeonTheme.textSp.title);
          }
        }
      } catch (e) {
        console.trace(e);
      }
    });
  }

  public setText(text: string): void {
    if (this.view) {
      Java.scheduleOnMainThread(() => {
        const String = API.JString;
        this.view.setText(String.$new(text));
      });
    }
  }
}
