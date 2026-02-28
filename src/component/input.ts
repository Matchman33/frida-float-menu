import { API } from "../api";
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
    if (!this.button) {
      console.warn(
        `[Switch:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.button.setText(String.$new(`${this.text}: ${this.value}`));
    });
  }

  protected createView(context: any): void {
    const Button = API.Button;
    const String = API.JString;

    this.button = Button.$new(context);
    this.button.setText(String.$new(`${this.text}: ${this.value}`));

    const self = this;

    // 点击按钮弹窗
    this.button.setOnClickListener(
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
      const builder = AlertDialogBuilder.$new(context);
      builder.setTitle(String.$new(this.title));

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
          implements: [API.DialogInterfaceOnClickListener],
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
              self.button.setText(String.$new(`${self.text}: ${self.value}`));
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
    if (!this.button) {
      console.warn(
        `[Switch:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.button.setText(String.$new(`${this.text}: ${this.value}`));
    });
  }
  protected createView(context: any): void {
    const Button = API.Button;
    const String = API.JString;

    this.button = Button.$new(context);
    this.button.setText(String.$new(`${this.text}: ${this.value}`));
    const self = this;

    // 点击按钮弹窗
    this.button.setOnClickListener(
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
      builder.setTitle(String.$new(this.title));

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
          implements: [API.DialogInterfaceOnClickListener],
          methods: {
            onClick: function (dialog: any, which: number) {
              const text =
                Java.cast(
                  input.getText(),
                  Java.use("java.lang.CharSequence"),
                ).toString() + "";
              self.value = text;
              self.button.setText(String.$new(`${self.text}: ${self.value}`));
              self.emit("valueChanged", text);
              if (self.handler) self.handler(text);
            },
          },
        }).$new(),
      );

      builder.setNegativeButton(String.$new("取消"), null);
      const LayoutParams = API.LayoutParams;
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
    if (this.button) {
      Java.scheduleOnMainThread(() => {
        const String = API.JString;
        this.button.setText(String.$new(text));
      });
    }
  }
}
