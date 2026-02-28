import { API } from "../api";
import { UIComponent } from "./ui-components";

export class Slider extends UIComponent {
  private min: number;
  private max: number;
  private step: number;
  private label: string;

  constructor(
    id: string,
    label: string,
    min: number,
    max: number,
    initialValue: number = min,
    step: number = 1,
  ) {
    super(id);
    this.label = label;
    this.min = min;
    this.max = max;
    this.step = step;
    // Ensure initial value is within bounds and aligned to step
    this.value = this.clampToStep(initialValue);
  }

  protected createView(context: any): void {
const LinearLayout = API.LinearLayout;
const TextView = API.TextView;
const SeekBar = API.SeekBar;
const Color = API.Color;
const String = API.JString;
const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
const LinearLayoutParams = API.LinearLayoutParams;

    // Create a horizontal LinearLayout to hold label and value
    const container = LinearLayout.$new(context);
    container.setOrientation(0); // HORIZONTAL
    container.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    container.setPadding(16, 8, 16, 8);

    // Label TextView
    const labelView = TextView.$new(context);
    labelView.setText(String.$new(this.label));
    labelView.setTextColor(Color.WHITE.value);
    labelView.setTextSize(14);
    labelView.setLayoutParams(
      LinearLayoutParams.$new(
        0, // width will be set by weight
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        1.0, // weight
      ),
    );

    // Value TextView (shows current value)
    const valueView = TextView.$new(context);
    valueView.setText(String.$new(this.value.toString()));
    valueView.setTextColor(Color.WHITE.value);
    valueView.setTextSize(14);
    valueView.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.WRAP_CONTENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    container.addView(labelView);
    container.addView(valueView);

    // SeekBar
    const seekBar = SeekBar.$new(context);
    seekBar.setMax(this.calculateSeekBarMax());
    seekBar.setProgress(this.valueToProgress(this.value));
    seekBar.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );

    // Create vertical layout to hold container and seekbar
    const verticalLayout = LinearLayout.$new(context);
    verticalLayout.setOrientation(1); // VERTICAL
    verticalLayout.setLayoutParams(
      LinearLayoutParams.$new(
        ViewGroupLayoutParams.MATCH_PARENT.value,
        ViewGroupLayoutParams.WRAP_CONTENT.value,
      ),
    );
    verticalLayout.addView(container);
    verticalLayout.addView(seekBar);

    // Store references on the view for later updates
    this.view = verticalLayout;
    (this.view as any).seekBar = seekBar;
    (this.view as any).valueView = valueView;
    (this.view as any).labelView = labelView;
    (this.view as any).container = container;

    const SeekBarOnSeekBarChangeListener =API.SeekBarOnSeekBarChangeListener
    const self = this;

    const changeListener = Java.registerClass({
      name:
        "com.frida.MySeekBarChangeListener" +
        Date.now() +
        Math.random().toString(36).substring(6),
      implements: [SeekBarOnSeekBarChangeListener],
      methods: {
        onProgressChanged: function (
          seekBar: any,
          progress: number,
          fromUser: boolean,
        ) {
          if (fromUser) {
            const newValue = self.progressToValue(progress);
            self.value = newValue;
            // Update value display
            Java.scheduleOnMainThread(() => {
              const valueView = (self.view as any).valueView;
              if (valueView) {
                valueView.setText(String.$new(newValue.toString()));
              }
            });
            self.emit("valueChanged", newValue);
          }
        },
        onStartTrackingTouch: function (seekBar: any) {
          // Do nothing
        },
        onStopTrackingTouch: function (seekBar: any) {
          // Do nothing
        },
      },
    });
    seekBar.setOnSeekBarChangeListener(changeListener.$new());
  }

  protected updateView(): void {
    if (!this.view) {
      console.warn(
        `[Slider:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const seekBar = (this.view as any).seekBar;
      const valueView = (this.view as any).valueView;
      if (seekBar) {
        seekBar.setProgress(this.valueToProgress(this.value));
      }
      if (valueView) {
        const String = API.JString
        valueView.setText(String.$new(this.value.toString()));
      }
    });
  }

  /**
   * Set slider label
   */
  public setLabel(label: string): void {
    this.label = label;
    if (!this.view) {
      console.warn(
        `[Slider:${this.id}] Cannot set label - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const labelView = (this.view as any).labelView;
      if (labelView) {
        const String = API.JString
        labelView.setText(String.$new(label));
      }
    });
  }

  /**
   * Set min, max, step values
   */
  public setRange(min: number, max: number, step: number = 1): void {
    this.min = min;
    this.max = max;
    this.step = step;
    this.value = this.clampToStep(this.value); // Re-clamp current value
    if (!this.view) {
      console.warn(
        `[Slider:${this.id}] Cannot set range - view not initialized`,
      );
      return;
    }
    Java.scheduleOnMainThread(() => {
      const seekBar = (this.view as any).seekBar;
      if (seekBar) {
        seekBar.setMax(this.calculateSeekBarMax());
        seekBar.setProgress(this.valueToProgress(this.value));
      }
    });
    this.updateView();
  }

  // Helper methods
  private calculateSeekBarMax(): number {
    // Number of steps between min and max
    return Math.round((this.max - this.min) / this.step);
  }

  private valueToProgress(value: number): number {
    // Convert value to seekbar progress (0 to max)
    return Math.round((value - this.min) / this.step);
  }

  private progressToValue(progress: number): number {
    // Convert seekbar progress to value
    const value = this.min + progress * this.step;
    // Clamp to min/max and round to nearest step
    return this.clampToStep(value);
  }

  private clampToStep(value: number): number {
    // Clamp to [min, max] and align to step
    let clamped = Math.max(this.min, Math.min(this.max, value));
    // Round to nearest step
    if (this.step > 0) {
      const steps = Math.round((clamped - this.min) / this.step);
      clamped = this.min + steps * this.step;
    }
    return clamped;
  }
}