import { API } from "../api";
import { applyStyle } from "./style/style";
import { DarkNeonTheme } from "./style/theme";
import { UIComponent } from "./ui-components";

// 选项类型定义
export interface CheckBoxOption {
  id: string;
  label: string;
  [key: string]: any;
}

export class CheckBoxGroup extends UIComponent {
  private optionsMap: Map<string, CheckBoxOption & { checked: boolean }> =
    new Map();
  private changeHandler?: (
    value: CheckBoxOption[],
    item?: { id: string; checked: boolean },
  ) => void;
  private valueChangeHandler?: (value: CheckBoxOption[]) => void;

  // ✅ 主显示控件：看起来像 Input，但点击弹出多选
  private triggerText: any;

  // 可自定义显示：最多显示多少个 label，超出用 “+N”
  private maxDisplayCount = 3;

  constructor(
    id: string,
    options: CheckBoxOption[],
    initialChecked: string[] = [],
    _columns: number = 3, // 保留参数不破坏外部调用，但不再使用
  ) {
    super(id);
    for (const opt of options) {
      const checked = initialChecked.includes(opt.id);
      this.optionsMap.set(opt.id, { ...opt, checked });
    }
    this.value = this.getCheckedValues();
  }

  public setOnChangeHandler(
    handler: (
      value: CheckBoxOption[],
      item?: { id: string; checked: boolean },
    ) => void,
  ) {
    this.changeHandler = handler;
  }

  public setOnValueChangeHandler(handler: (value: CheckBoxOption[]) => void) {
    this.valueChangeHandler = handler;
  }

  public setMaxDisplayCount(n: number) {
    this.maxDisplayCount = Math.max(1, n);
    this.updateView();
  }

  protected createView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const TextView = API.TextView;
    const String = API.JString;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const Gravity = API.Gravity;

    // 容器（可选：你也可以直接用 triggerText 作为 view）
    const root = LinearLayout.$new(context);
    root.setOrientation(LinearLayout.VERTICAL.value);
    root.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    // “下拉框/输入框”样式触发器
    const trigger = TextView.$new(context);
    trigger.setGravity(Gravity.CENTER_VERTICAL.value);
    trigger.setSingleLine(true);

    // 让它看起来像一个输入框（点击弹窗）
    applyStyle(trigger, "inputTrigger", DarkNeonTheme);

    // 右侧加个小箭头（纯文本，免依赖图标）
    // 你也可以换成 "▾" 或 "▼"
    trigger.setText(String.$new(this.buildDisplayText() + "  ▾"));

    // 点击弹出多选
    const ViewOnClickListener = API.OnClickListener;
    const self = this;
    const clickListener = Java.registerClass({
      name:
        "com.frida.MultiSelectTriggerClick" +
        Date.now() +
        Math.random().toString(36).slice(2),
      implements: [ViewOnClickListener],
      methods: {
        onClick: function () {
          self.openMultiSelectDialog(context);
        },
      },
    });

    trigger.setOnClickListener(clickListener.$new());

    root.addView(trigger);

    this.view = root;
    this.triggerText = trigger;
  }

  // ✅ 弹窗：多选列表
  // 不使用全选和全不选，单击选中和取消选中是有动画的。用了你的代码以后，我发现点击全选勾选中的项，点击全部取消就有动画。但是如果是单击选中的，点击全部取消就没有动画。想办法修复吧，而且我感觉这个函数好长啊，帮我模块化一下。// ✅ 弹窗：多选列表
  private openMultiSelectDialog(context: any) {
    const AlertDialogBuilder = API.AlertDialogBuilder; // 你 API 里如果叫 AlertDialog$Builder 就按你的实际名称改一下
    const String = API.JString;

    // options arrays
    const opts = Array.from(this.optionsMap.values());
    const labels: string[] = opts.map((o) => o.label);
    const checkedArr: boolean[] = opts.map((o) => !!o.checked);

    // Java CharSequence[] / boolean[]
    const csArray = Java.array(
      "java.lang.CharSequence",
      labels.map((s) => String.$new(s) as any),
    );
    const boolArray = Java.array("boolean", checkedArr);

    const DialogMultiChoiceListener = Java.use(
      "android.content.DialogInterface$OnMultiChoiceClickListener",
    );
    const DialogClickListener = Java.use(
      "android.content.DialogInterface$OnClickListener",
    );

    const self = this;

    // 多选点击：只更新内部状态，不立刻关闭
    const multiListener = Java.registerClass({
      name:
        "com.frida.MultiChoiceListener" +
        Date.now() +
        Math.random().toString(36).slice(2),
      implements: [DialogMultiChoiceListener],
      methods: {
        onClick: function (_dialog: any, which: number, isChecked: boolean) {
          const opt = opts[which];
          self.optionsMap.set(opt.id, { ...opt, checked: isChecked });
          self.value = self.getCheckedValues();
          self.emit("change", self.value, { id: opt.id, checked: isChecked });
          if (self.changeHandler)
            setImmediate(() =>
              self.changeHandler!(self.value, {
                id: opt.id,
                checked: isChecked,
              }),
            );
        },
      },
    });

    // 确定按钮：刷新显示 + valueChanged
    const okListener = Java.registerClass({
      name:
        "com.frida.MultiChoiceOk" +
        Date.now() +
        Math.random().toString(36).slice(2),
      implements: [DialogClickListener],
      methods: {
        onClick: function (dialog: any, _which: number) {
          self.value = self.getCheckedValues();
          self.updateView();
          self.emit("valueChanged", self.value);
          if (self.valueChangeHandler)
            setImmediate(() => self.valueChangeHandler!(self.value));
          dialog.dismiss();
        },
      },
    });

    // 取消按钮：不改
    const cancelListener = Java.registerClass({
      name:
        "com.frida.MultiChoiceCancel" +
        Date.now() +
        Math.random().toString(36).slice(2),
      implements: [DialogClickListener],
      methods: {
        onClick: function (dialog: any, _which: number) {
          dialog.dismiss();
        },
      },
    });

    // 构建对话框
    // ⚠️ 注意：你 API 的 AlertDialogBuilder 可能不一样，如果你现有 radiobutton 下拉框用的是哪个 builder，就照那个改
    const builder = AlertDialogBuilder.$new(context);
    builder.setTitle(String.$new("请选择"));

    builder.setMultiChoiceItems(csArray, boolArray, multiListener.$new());
    builder.setPositiveButton(String.$new("确定"), okListener.$new());
    builder.setNegativeButton(String.$new("取消"), cancelListener.$new());

    const dialog = builder.create();

    // ✅ 关键：把 Dialog 变成 Overlay Window，否则没有 Activity token 会 BadToken
    const WindowManagerLP = Java.use("android.view.WindowManager$LayoutParams");
    const BuildVERSION = Java.use("android.os.Build$VERSION");

    const win = dialog.getWindow();
    if (win) {
      // Android 8.0+ 用 TYPE_APPLICATION_OVERLAY；8.0 以下用 TYPE_PHONE（或 TYPE_SYSTEM_ALERT）
      if (BuildVERSION.SDK_INT.value >= 26) {
        win.setType(WindowManagerLP.TYPE_APPLICATION_OVERLAY.value);
      } else {
        win.setType(WindowManagerLP.TYPE_PHONE.value);
        // 也可以用：WindowManagerLP.TYPE_SYSTEM_ALERT.value
      }

      // （可选但常用）防止抢焦点/输入法问题
      win.addFlags(WindowManagerLP.FLAG_NOT_FOCUSABLE.value);
      win.addFlags(WindowManagerLP.FLAG_NOT_TOUCH_MODAL.value);
    }

    dialog.show();
  }

  protected updateView(): void {
    if (!this.triggerText) return;
    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.triggerText.setText(String.$new(this.buildDisplayText() + "  ▾"));
    });
  }

  private buildDisplayText(): string {
    const selected = this.getCheckedValues();
    if (selected.length === 0) return "请选择";

    const labels = selected.map((x) => x.label);
    if (labels.length <= this.maxDisplayCount) return labels.join("、");

    const shown = labels.slice(0, this.maxDisplayCount).join("、");
    const rest = labels.length - this.maxDisplayCount;
    return `${shown} +${rest}`;
  }

  public getCheckedValues(): CheckBoxOption[] {
    return Array.from(this.optionsMap.values()).filter((op) => op.checked);
  }

  public setChecked(id: string, checked: boolean): void {
    if (!this.optionsMap.has(id)) {
      console.warn(
        `[CheckBoxGroup:${this.id}] Option with id "${id}" not found`,
      );
      return;
    }
    const opt = this.optionsMap.get(id)!;
    this.optionsMap.set(id, { ...opt, checked });
    this.value = this.getCheckedValues();
    this.updateView();

    this.emit("change", this.value, { id, checked });
    this.emit("valueChanged", this.value);

    if (this.changeHandler)
      this.changeHandler(this.value, { id: opt.id, checked });
    if (this.valueChangeHandler) this.valueChangeHandler(this.value);
  }

  public setCheckedValues(checkedIds: string[]): void {
    // 全部先清空
    for (const [id, opt] of this.optionsMap.entries()) {
      this.optionsMap.set(id, { ...opt, checked: false });
    }
    for (const id of checkedIds) {
      if (this.optionsMap.has(id)) {
        const opt = this.optionsMap.get(id)!;
        this.optionsMap.set(id, { ...opt, checked: true });
      }
    }
    this.value = this.getCheckedValues();
    this.updateView();

    this.emit("change", this.value);
    this.emit("valueChanged", this.value);
    if (this.changeHandler) this.changeHandler(this.value);
    if (this.valueChangeHandler) this.valueChangeHandler(this.value);
  }

  public getOptions(): CheckBoxOption[] {
    return Array.from(this.optionsMap.values()).slice();
  }
}
