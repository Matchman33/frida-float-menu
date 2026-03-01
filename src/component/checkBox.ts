import { API } from "../api";
import { UIComponent } from "./ui-components";

// 选项类型定义
export interface CheckBoxOption {
  id: string; // 选项唯一标识
  label: string; // 显示文本
  [key: string]: any;
}

export class CheckBoxGroup extends UIComponent {
  private optionsMap: Map<string, CheckBoxOption & { checked: boolean }> =
    new Map();
  private checkBoxMap: Map<string, any> = new Map(); // 存储每个选项对应的 CheckBox 对象
  private changeHandler?: (
    value: CheckBoxOption[],
    item?: { id: string; checked: boolean },
  ) => void;
  private valueChangeHandler?: (value: CheckBoxOption[]) => void;
  private columns: number; // 每行显示的列数
  /**
   * @param id 组件唯一id
   * @param options 选项组
   * @param initialChecked 默认选中的id数组
   * @param columns 每行显示的列数
   */
  constructor(
    id: string,
    options: CheckBoxOption[],
    initialChecked: string[] = [],
    columns: number = 3,
  ) {
    super(id);
    // 初始化选中状态
    this.columns = columns ?? (Math.ceil(options.length / 2) || 3);
    for (const opt of options) {
      const checked = initialChecked.includes(opt.id);
      this.optionsMap.set(opt.id, { ...opt, checked });
    }
    // value 可以存储当前选中的 id 数组，方便外部读取
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
  protected createView(context: any): void {
    // 使用 GridLayout 实现自动换行
    const GridLayout = API.GridLayout;
    const CheckBox = API.CheckBox;
    const String = API.JString;
    const Color = API.Color;
    const GridLayoutParams = API.GridLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;

    // 创建 GridLayout 作为容器
    const layout = GridLayout.$new(context);
    layout.setColumnCount(this.columns);
    layout.setLayoutParams(
      ViewGroupLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    this.view = layout;

    const self = this;
    const OnCheckedChangeListener = API.OnCheckedChangeListener;

    // 遍历选项，创建 CheckBox
    for (const opt of this.optionsMap.values()) {
      const checkBox = CheckBox.$new(context);
      checkBox.setText(String.$new(opt.label));
      checkBox.setTextColor(Color.WHITE.value);
      checkBox.setChecked(opt.checked || false);
      checkBox.setPadding(16, 8, 16, 8);

      const params = GridLayoutParams.$new();
      params.width = 0; // 宽度为0，结合权重填充
      params.height = ViewGroupLayoutParams.WRAP_CONTENT.value;
      params.columnSpec = GridLayout.spec(GridLayout.UNDEFINED.value, 1); // 权重为1，平均分配宽度
      params.rowSpec = GridLayout.spec(GridLayout.UNDEFINED.value); // 自动分配行
      checkBox.setLayoutParams(params);
      // 保存 CheckBox 对象
      this.checkBoxMap.set(opt.id, checkBox);

      // 创建选中状态变化监听器
      const listener = Java.registerClass({
        name:
          "com.frida.CheckBoxListener" +
          Date.now() +
          Math.random().toString(36).substring(6),
        implements: [OnCheckedChangeListener],
        methods: {
          onCheckedChanged: function (buttonView: any, isChecked: boolean) {
            // 更新内部状态
            self.optionsMap.set(opt.id, {
              ...opt,
              checked: isChecked,
            });
            // 更新 value
            self.value = self.getCheckedValues();
            // 触发自定义事件，传递当前选中的 id 数组和具体变化的选项
            self.emit("change", self.value, {
              id: opt.id,
              checked: isChecked,
            });
            if (self.changeHandler)
              setImmediate(() => {
                self.changeHandler!(self.value, {
                  id: opt.id,
                  checked: isChecked,
                });
              });

            self.emit("valueChanged", self.value);
            if (self.valueChangeHandler)
              setImmediate(() => self.valueChangeHandler!(self.value));
          },
        },
      }).$new();

      checkBox.setOnCheckedChangeListener(listener);
      layout.addView(checkBox);
    }
  }

  protected updateView(): void {
    // 当外部调用 setValue 或 setChecked 时，需要同步 UI 状态
    if (!this.view) return;
    Java.scheduleOnMainThread(() => {
      for (const [id, checkBox] of this.checkBoxMap.entries()) {
        const checked = this.optionsMap.get(id)?.checked || false;
        if (checkBox.isChecked() !== checked) {
          checkBox.setChecked(checked);
        }
      }
    });
  }

  /**
   * 获取当前选中的选项
   */
  public getCheckedValues(): CheckBoxOption[] {
    return Array.from(this.optionsMap.values()).filter((op) => op.checked);
  }

  /**
   * 设置指定选项的选中状态
   * @param id 选项 id
   * @param checked 是否选中
   */
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
    this.updateView(); // 同步 UI
    this.emit("change", this.value, { id, checked });
    this.emit("valueChanged", this.value);

    if (this.changeHandler)
      this.changeHandler(this.value, {
        id: opt.id,
        checked: checked,
      });

    if (this.valueChangeHandler) this.valueChangeHandler(this.value);
  }

  /**
   * 批量设置选中状态
   * @param checkedIds 需要选中的 id 数组
   */
  public setCheckedValues(checkedIds: string[]): void {
    // 先将所有选项设为 false
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

  /**
   * 获取所有选项的定义
   */
  public getOptions(): CheckBoxOption[] {
    return Array.from(this.optionsMap.values()).slice();
  }
}
