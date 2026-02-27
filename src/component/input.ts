import { UIComponent } from "./ui-components";

export class NumberInput extends UIComponent {
  private text: string;
  private hint: string;
  private min: number | null;
  private max: number | null;
  private handler?: (value: number) => void;

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
  ) {
    super(id);
    this.value = initialValue;
    this.text = text;
    this.hint = hint;
    this.min = min;
    this.max = max;
  }

  protected updateView(): void {}

  protected createView(context: any): void {
    const Button = Java.use("android.widget.Button");
    const String = Java.use("java.lang.String");

    this.view = Button.$new(context);
    this.view.setText(String.$new(this.text));

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
      builder.setTitle(String.$new("请输入"));

      const input = EditText.$new(context);
      input.setHint(String.$new(this.hint));
      input.setText(
        String.$new(this.value + ""),
        TextViewBufferType.NORMAL.value,
      );
      // 设置输入类型为数字（可带小数和符号）
      input.setInputType(
        InputType.TYPE_CLASS_NUMBER.value |
          InputType.TYPE_NUMBER_FLAG_DECIMAL.value |
          InputType.TYPE_NUMBER_FLAG_SIGNED.value,
      );

      builder.setView(input);

      const self = this;

      builder.setPositiveButton(
        String.$new("确认"),
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
              const text =
                Java.cast(
                  input.getText(),
                  Java.use("java.lang.CharSequence"),
                ).toString() + "";

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

              self.emit("valueChanged", self.value);
              if (self.handler) self.handler(self.value);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("取消"), null);

      const dialog = builder.create();
      const window = dialog.getWindow();
      if (window) {
        // 设置窗口类型为系统悬浮窗（与悬浮窗一致）
        window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value); // API 26+
      }
      dialog.show();
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
  protected updateView(): void {}
  private text: string;
  private hint: string;
  private handler?: (value: string) => void;

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
  ) {
    super(id);
    this.text = text;
    this.hint = hint;
    this.value = initialValue;
  }

  protected createView(context: any): void {
    const Button = Java.use("android.widget.Button");
    const String = Java.use("java.lang.String");

    this.view = Button.$new(context);
    this.view.setText(String.$new(this.text));

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

  public setOnValueChange(handler: (value: string) => void) {
    this.handler = handler;
  }

  private showDialog(context: any): void {
    Java.scheduleOnMainThread(() => {
      const AlertDialogBuilder = Java.use("android.app.AlertDialog$Builder");
      const EditText = Java.use("android.widget.EditText");
      const String = Java.use("java.lang.String");
      const TextViewBufferType = Java.use("android.widget.TextView$BufferType");
      const builder = AlertDialogBuilder.$new(context);
      builder.setTitle(String.$new("请输入"));

      const input = EditText.$new(context);
      input.setHint(String.$new(this.hint));
      input.setText(String.$new(this.value), TextViewBufferType.NORMAL.value);

      builder.setView(input);

      const self = this;

      builder.setPositiveButton(
        String.$new("确认"),
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
              const text =
                Java.cast(
                  input.getText(),
                  Java.use("java.lang.CharSequence"),
                ).toString() + "";
              self.value = text;
              self.emit("valueChanged", text);
              if (self.handler) self.handler(text);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("取消"), null);
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

  public setText(text: string): void {
    if (this.view) {
      Java.scheduleOnMainThread(() => {
        const String = Java.use("java.lang.String");
        this.view.setText(String.$new(text));
      });
    }
  }
}
