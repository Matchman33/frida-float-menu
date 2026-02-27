import { UIComponent } from "./ui-components";

export class NumberInput extends UIComponent {
  private title: string;
  private hint: string;
  private min: number | null;
  private max: number | null;
  private step: number | null;

  constructor(
    id: string,
    initialValue: number = 0,
    title: string = "Input Number",
    hint: string = "",
    min: number | null = null,
    max: number | null = null,
    step: number | null = null,
  ) {
    super(id);
    this.value = initialValue;
    this.title = title;
    this.hint = hint;
    this.min = min;
    this.max = max;
    this.step = step;
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(`[NumberInput:${this.id}] Cannot update view - view not initialized`);
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = Java.use("java.lang.String");
      this.view.setText(String.$new(this.value.toString()));
    });
  }

  protected createView(context: any): void {
    const Button = Java.use("android.widget.Button");
    const String = Java.use("java.lang.String");

    this.view = Button.$new(context);
    this.view.setText(String.$new(this.value.toString()));

    const self = this;

    // 点击按钮弹窗
    this.view.setOnClickListener(
      Java.registerClass({
        name:
          "com.frida.NumberInputClick" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [Java.use("android.view.View$OnClickListener")],
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
      const AlertDialogBuilder = Java.use("android.app.AlertDialog$Builder");
      const EditText = Java.use("android.widget.EditText");
      const String = Java.use("java.lang.String");
      const TextViewBufferType = Java.use("android.widget.TextView$BufferType");
      const InputType = Java.use("android.text.InputType");
      const LayoutParams = Java.use("android.view.WindowManager$LayoutParams");

      const builder = AlertDialogBuilder.$new(context);
      builder.setTitle(String.$new(this.title));

      const input = EditText.$new(context);
      input.setHint(String.$new(this.hint));
      input.setText(String.$new(this.value.toString()), TextViewBufferType.NORMAL.value);
      // 设置输入类型为数字（可带小数和符号）
      input.setInputType(
        InputType.TYPE_CLASS_NUMBER.value |
          InputType.TYPE_NUMBER_FLAG_DECIMAL.value |
          InputType.TYPE_NUMBER_FLAG_SIGNED.value,
      );

      builder.setView(input);

      const self = this;

      builder.setPositiveButton(
        String.$new("OK"),
        Java.registerClass({
          name:
            "com.frida.NumberInputOK" +
            Date.now() +
            Math.random().toString(36).substring(6),
          implements: [
            Java.use("android.content.DialogInterface$OnClickListener"),
          ],
          methods: {
            onClick: function (dialog: any, which: number) {
              // 安全获取输入文本
              const editable = input.getText();
              const CharSequence = Java.use("java.lang.CharSequence");
              const text = Java.cast(editable, CharSequence).toString();

              if (text === "") {
                // 空输入视为 0
                self.value = 0;
              } else {
                const num = parseFloat(text);
                if (!isNaN(num)) {
                  self.value = num;
                } else {
                  // 无效输入，保持原值
                  return;
                }
              }

              // 应用约束
              self.applyConstraints();

              // 更新按钮文本
              self.updateView();
              self.emit("valueChanged", self.value);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("Cancel"), null);

      const dialog = builder.create();
      const window = dialog.getWindow();
      if (window) {
        // 设置窗口类型为系统悬浮窗（与悬浮窗一致）
        window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value); // API 26+
      }
      dialog.show();
    });
  }

  private applyConstraints(): void {
    let constrained = this.value as number;
    if (this.min !== null) constrained = Math.max(this.min, constrained);
    if (this.max !== null) constrained = Math.min(this.max, constrained);
    if (this.step !== null && this.step > 0) {
      const steps = Math.round(constrained / this.step);
      constrained = steps * this.step;
    }
    this.value = constrained;
  }

  // 以下为原有公共方法（稍作调整）

  public setHint(hint: string): void {
    this.hint = hint;
    // 提示文本只在对话框中使用，无需实时更新视图
  }

  public setConstraints(min: number | null, max: number | null, step: number | null): void {
    this.min = min;
    this.max = max;
    this.step = step;
    // 重新验证当前值
    this.applyConstraints();
    this.updateView();
  }

  public getNumber(): number {
    return this.value as number;
  }

  public setNumber(value: number): void {
    this.value = value;
    this.applyConstraints();
    this.updateView();
  }
}
export class TextInput extends UIComponent {
  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[TextInput:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = Java.use("java.lang.String");
      this.view.setText(String.$new(this.value));
    });
  }
  private title: string;
  private hint: string;

  constructor(
    id: string,
    title: string = "Input",
    hint: string = "",
    initialValue: string = "",
  ) {
    super(id);
    this.title = title;
    this.hint = hint;
    this.value = initialValue;
  }

  protected createView(context: any): void {
    const Button = Java.use("android.widget.Button");
    const String = Java.use("java.lang.String");

    this.view = Button.$new(context);
    this.view.setText(String.$new(this.value || this.hint || "Click to input"));

    const self = this;

    // 点击按钮弹窗
    this.view.setOnClickListener(
      Java.registerClass({
        name:
          "com.frida.AlertTextInputClick" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [Java.use("android.view.View$OnClickListener")],
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

  private showDialog(context: any): void {
    Java.scheduleOnMainThread(() => {
      const AlertDialogBuilder = Java.use("android.app.AlertDialog$Builder");
      const EditText = Java.use("android.widget.EditText");
      const String = Java.use("java.lang.String");
      const TextViewBufferType = Java.use("android.widget.TextView$BufferType");
      const builder = AlertDialogBuilder.$new(context);
      builder.setTitle(String.$new(this.title));

      const input = EditText.$new(context);
      input.setHint(String.$new(this.hint));
      input.setText(String.$new(this.value), TextViewBufferType.NORMAL.value);

      builder.setView(input);

      const self = this;

      builder.setPositiveButton(
        String.$new("OK"),
        Java.registerClass({
          name:
            "com.frida.AlertTextInputOK" +
            Date.now() +
            Math.random().toString(36).substring(6),
          implements: [
            Java.use("android.content.DialogInterface$OnClickListener"),
          ],
          methods: {
            onClick: function (dialog: any, which: number) {
              const editable = input.getText();
              const text =
                Java.cast(
                  editable,
                  Java.use("java.lang.CharSequence"),
                ).toString() + "";
              self.value = text;
              self.emit("valueChanged", text);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("Cancel"), null);
      const LayoutParams = Java.use("android.view.WindowManager$LayoutParams");
      const dialog = builder.create();
      // 关键步骤：修改对话框窗口的类型
      const window = dialog.getWindow();
      if (window) {
        // 设置窗口类型为系统悬浮窗（与你的悬浮窗一致）
        window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value); // API 26+
        // 或者对于低版本：LayoutParams.TYPE_PHONE (2002)
      }
      dialog.show();
    });
  }

  public getText(): string {
    return this.value;
  }

  public setText(text: string): void {
    this.value = text;
    if (this.view) {
      Java.scheduleOnMainThread(() => {
        const String = Java.use("java.lang.String");
        this.view.setText(String.$new(text));
      });
    }
  }
}
