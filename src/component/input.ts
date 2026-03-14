import { API } from "../api";
import { Logger } from "../logger";
import { applyStyle, dp } from "./style/style";
import { UIComponent } from "./ui-components";

function setDialogOverlayType(dialog: any) {
  try {
    const window = dialog.getWindow();
    if (!window) return;

    const LayoutParams = API.LayoutParams;
    const BuildVERSION = API.BuildVERSION;

    if (BuildVERSION.SDK_INT.value >= 26) {
      window.setType(LayoutParams.TYPE_APPLICATION_OVERLAY.value);
    } else {
      window.setType(LayoutParams.TYPE_PHONE.value);
    }
  } catch (e) {
    Logger.instance.warn(`[Input] Failed to set dialog overlay type: ${e}`);
  }
}

abstract class BaseInputButton extends UIComponent {
  protected title: string;
  protected hint: string;
  protected isShowDialog: boolean = false;

  protected buttonView: any;
  protected buttonLabelView: any;
  protected buttonIconView: any;

  constructor(id: string, title: string, hint: string) {
    super(id);
    this.title = title;
    this.hint = hint;
  }

  protected createBaseView(context: any): void {
    const LinearLayout = API.LinearLayout;
    const LinearLayoutParams = API.LinearLayoutParams;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const TextView = API.TextView;
    const Gravity = API.Gravity;
    const String = API.JString;

    const root = LinearLayout.$new(context);
    root.setOrientation(LinearLayout.HORIZONTAL.value);
    root.setGravity(Gravity.CENTER_VERTICAL.value);
    applyStyle(root, "inputButton", this.menu.options.theme!);

    const labelView = TextView.$new(context);
    labelView.setText(String.$new(this.buildDisplayText()));
    applyStyle(labelView, "text", this.menu.options.theme!);
    labelView.setTextSize(2, 14);
    try {
      labelView.setTypeface(null, 1);
    } catch (_e) {}
    labelView.setSingleLine(true);
    labelView.setGravity(Gravity.LEFT.value | Gravity.CENTER_VERTICAL.value);
    labelView.setLayoutParams(
      LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0),
    );

    const iconView = TextView.$new(context);
    iconView.setText(String.$new("✎"));
    iconView.setTextColor(this.menu.options.theme!.colors.accent);
    iconView.setTextSize(2, 16);
    iconView.setGravity(Gravity.CENTER.value);

    const iconLp = LinearLayoutParams.$new(
      ViewGroupLayoutParams.WRAP_CONTENT.value,
      ViewGroupLayoutParams.WRAP_CONTENT.value,
    );
    iconLp.leftMargin = dp(context, 12);
    iconView.setLayoutParams(iconLp);

    root.addView(labelView);
    root.addView(iconView);

    this.view = root;
    this.buttonView = root;
    this.buttonLabelView = labelView;
    this.buttonIconView = iconView;
  }

  protected refreshButtonText(): void {
    if (!this.buttonLabelView) return;

    Java.scheduleOnMainThread(() => {
      const String = API.JString;
      this.buttonLabelView.setText(String.$new(this.buildDisplayText()));
    });
  }

  protected abstract buildDisplayText(): string;
}

export class NumberInput extends BaseInputButton {
  private min: number | null = null;
  private max: number | null = null;
  private handler?: (value: number) => void;

  constructor(
    id: string,
    initialValue: number = 0,
    title: string = "请输入数值",
    hint: string = "请输入数值",
  ) {
    super(id, title, hint);
    this.value = initialValue;
  }

  protected buildDisplayText(): string {
    const hasValue =
      this.value !== null &&
      this.value !== undefined &&
      !isNaN(this.value as number);
    return hasValue
      ? `${this.title}: ${this.value}`
      : `${this.title}: ${this.hint}`;
  }

  protected createView(context: any): void {
    this.createBaseView(context);

    const self = this;
    const clickListener = Java.registerClass({
      name:
        "com.frida.NumberInputButtonClick" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [API.OnClickListener],
      methods: {
        onClick: function () {
          if (self.isShowDialog) return;
          self.isShowDialog = true;
          self.showDialog(context);
        },
      },
    });

    this.buttonView.setClickable(true);
    this.buttonView.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    this.applyConstraints();
    this.refreshButtonText();
  }

  private showDialog(context: any): void {
    Java.scheduleOnMainThread(() => {
      try {
        const AlertDialogBuilder = API.AlertDialogBuilder;
        const EditText = API.EditText;
        const JString = API.JString;
        const LinearLayout = API.LinearLayout;
        const LinearLayoutParams = API.LinearLayoutParams;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const InputType = Java.use("android.text.InputType");
        const TextViewBufferType = API.TextViewBufferType;
        const builder = AlertDialogBuilder.$new(context);
        builder.setTitle(JString.$new(this.title));

        const input = EditText.$new(context);
        input.setHint(JString.$new(this.hint));
        input.setText(
          JString.$new(String(this.value ?? "")),
          TextViewBufferType.NORMAL.value,
        );
        // applyStyle(input, "inputField", this.menu.options.theme!);
        try {
          input.setInputType(
            InputType.TYPE_CLASS_NUMBER.value |
              InputType.TYPE_NUMBER_FLAG_SIGNED.value |
              InputType.TYPE_NUMBER_FLAG_DECIMAL.value,
          );
        } catch (_e) {}

        const lp = LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        );
        input.setLayoutParams(lp);

        const container = LinearLayout.$new(context);
        container.setPadding(
          dp(context, 16),
          dp(context, 12),
          dp(context, 16),
          dp(context, 8),
        );
        container.addView(input);
        builder.setView(container);

        const self = this;

        builder.setPositiveButton(
          JString.$new("确认"),
          Java.registerClass({
            name:
              "com.frida.NumberInputOK" +
              Date.now() +
              Math.random().toString(36).substring(6),
            implements: [API.DialogInterfaceOnClickListener],
            methods: {
              onClick: function (_dialog: any, _which: number) {
                self.isShowDialog = false;
                try {
                  const raw =
                    Java.cast(
                      input.getText(),
                      Java.use("java.lang.CharSequence"),
                    ).toString() + "";
                  const parsed = parseFloat(raw.trim());
                  if (!isNaN(parsed)) {
                    self.value = parsed;
                    self.applyConstraints();
                    self.refreshButtonText();
                    self.emit("valueChanged", self.value);
                    if (self.handler) self.handler(self.value as number);
                  }
                } catch (e) {
                  Logger.instance.error(`[NumberInput:${self.id}] ${e}`);
                }
              },
            },
          }).$new(),
        );

        builder.setNegativeButton(
          JString.$new("取消"),
          Java.registerClass({
            name:
              "com.frida.NumberInputCancel" +
              Date.now() +
              Math.random().toString(36).substring(6),
            implements: [API.DialogInterfaceOnClickListener],
            methods: {
              onClick: function (_dialog: any, _which: number) {
                self.isShowDialog = false;
              },
            },
          }).$new(),
        );

        const dialog = builder.create();
        setDialogOverlayType(dialog);
        dialog.show();
      } catch (e) {
        this.isShowDialog = false;
        Logger.instance.error(
          `[NumberInput:${this.id}] Failed to show dialog: ${e}`,
        );
      }
    });
  }

  public onValueChange(handler: (value: number) => void) {
    this.handler = handler;
  }

  private applyConstraints(): void {
    let constrained = this.value as number;
    if (this.min !== null) constrained = Math.max(this.min, constrained);
    if (this.max !== null) constrained = Math.min(this.max, constrained);
    this.value = constrained;
  }

  public setHint(hint: string): void {
    this.hint = hint;
  }

  public setConstraints(min: number | null, max: number | null): void {
    this.min = min;
    this.max = max;
    this.applyConstraints();
    this.refreshButtonText();
  }

  public getNumber(): number {
    return this.value as number;
  }

  public setNumber(value: number): void {
    this.value = value;
    this.applyConstraints();
    this.refreshButtonText();
  }
}

export class TextInput extends BaseInputButton {
  private handler?: (value: string) => void;

  constructor(
    id: string,
    initialValue: string = "",
    title: string = "请输入文本",
    hint: string = "请输入文本",
  ) {
    super(id, title, hint);
    this.value = initialValue;
  }

  protected buildDisplayText(): string {
    const text = ((this.value ?? "") + "").trim();
    return text.length > 0
      ? `${this.title}: ${text}`
      : `${this.title}: ${this.hint}`;
  }

  protected createView(context: any): void {
    this.createBaseView(context);

    const self = this;
    const clickListener = Java.registerClass({
      name:
        "com.frida.TextInputButtonClick" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [API.OnClickListener],
      methods: {
        onClick: function () {
          if (self.isShowDialog) return;
          self.isShowDialog = true;
          self.showDialog(context);
        },
      },
    });

    this.buttonView.setClickable(true);
    this.buttonView.setOnClickListener(clickListener.$new());
  }

  protected updateView(): void {
    this.refreshButtonText();
  }

  protected emitValue(value: any) {
    this.emit("valueChanged", value);
  }

  public onValueChange(handler: (value: string) => void) {
    this.handler = handler;
  }

  private showDialog(context: any): void {
    Java.scheduleOnMainThread(() => {
      try {
        const AlertDialogBuilder = API.AlertDialogBuilder;
        const EditText = API.EditText;
        const String = API.JString;
        const TextViewBufferType = API.TextViewBufferType;
        const LinearLayoutParams = API.LinearLayoutParams;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const LinearLayout = API.LinearLayout;

        const builder = AlertDialogBuilder.$new(context);
        builder.setTitle(String.$new(this.title));

        const input = EditText.$new(context);
        input.setHint(String.$new(this.hint));
        input.setText(
          String.$new(this.value ?? ""),
          TextViewBufferType.NORMAL.value,
        );
        // applyStyle(input, "inputField", this.menu.options.theme!);
        const lp = LinearLayoutParams.$new(
          ViewGroupLayoutParams.MATCH_PARENT.value,
          ViewGroupLayoutParams.WRAP_CONTENT.value,
        );
        input.setLayoutParams(lp);

        const container = LinearLayout.$new(context);
        container.setPadding(
          dp(context, 16),
          dp(context, 12),
          dp(context, 16),
          dp(context, 8),
        );
        container.addView(input);
        builder.setView(container);

        const self = this;

        builder.setPositiveButton(
          String.$new("确认"),
          Java.registerClass({
            name:
              "com.frida.TextInputOK" +
              Date.now() +
              Math.random().toString(36).substring(6),
            implements: [API.DialogInterfaceOnClickListener],
            methods: {
              onClick: function (_dialog: any, _which: number) {
                self.isShowDialog = false;
                const text =
                  Java.cast(
                    input.getText(),
                    Java.use("java.lang.CharSequence"),
                  ).toString() + "";
                self.value = text.trim();
                self.refreshButtonText();
                self.emit("valueChanged", self.value);
                if (self.handler) self.handler(self.value as string);
              },
            },
          }).$new(),
        );

        builder.setNegativeButton(
          String.$new("取消"),
          Java.registerClass({
            name:
              "com.frida.TextInputCancel" +
              Date.now() +
              Math.random().toString(36).substring(6),
            implements: [API.DialogInterfaceOnClickListener],
            methods: {
              onClick: function (_dialog: any, _which: number) {
                self.isShowDialog = false;
              },
            },
          }).$new(),
        );

        const dialog = builder.create();
        setDialogOverlayType(dialog);
        dialog.show();
      } catch (e) {
        this.isShowDialog = false;
        Logger.instance.error(
          `[TextInput:${this.id}] Failed to show dialog: ${e}`,
        );
      }
    });
  }

  public setText(text: string): void {
    this.value = text ?? "";
    this.refreshButtonText();
  }
}
