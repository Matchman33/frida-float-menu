import { API } from "../api";
import { Logger } from "../logger";
import { UIComponent } from "./ui-components";
export class Slider extends UIComponent {
    constructor(id, label, min, max, initialValue = min, step = 1, handler) {
        super(id);
        this.label = label;
        this.min = min;
        this.max = max;
        this.step = step;
        this.handler = handler;
        this.value = this.clampToStep(initialValue);
    }
    createView(context) {
        const LinearLayout = API.LinearLayout;
        const TextView = API.TextView;
        const SeekBar = API.SeekBar;
        const Color = API.Color;
        const String = API.JString;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const LinearLayoutParams = API.LinearLayoutParams;
        const container = LinearLayout.$new(context);
        container.setOrientation(0);
        container.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        container.setPadding(16, 8, 16, 8);
        const labelView = TextView.$new(context);
        labelView.setText(String.$new(this.label));
        labelView.setTextColor(Color.WHITE.value);
        labelView.setTextSize(14);
        labelView.setLayoutParams(LinearLayoutParams.$new(0, ViewGroupLayoutParams.WRAP_CONTENT.value, 1.0));
        const valueView = TextView.$new(context);
        valueView.setText(String.$new(this.value.toString()));
        valueView.setTextColor(Color.WHITE.value);
        valueView.setTextSize(14);
        valueView.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.WRAP_CONTENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        container.addView(labelView);
        container.addView(valueView);
        const seekBar = SeekBar.$new(context);
        seekBar.setMax(this.calculateSeekBarMax());
        seekBar.setProgress(this.valueToProgress(this.value));
        seekBar.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        const verticalLayout = LinearLayout.$new(context);
        verticalLayout.setOrientation(1);
        verticalLayout.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
        verticalLayout.addView(container);
        verticalLayout.addView(seekBar);
        this.view = verticalLayout;
        this.view.seekBar = seekBar;
        this.view.valueView = valueView;
        this.view.labelView = labelView;
        this.view.container = container;
        const SeekBarOnSeekBarChangeListener = API.SeekBarOnSeekBarChangeListener;
        const self = this;
        const changeListener = Java.registerClass({
            name: "com.frida.MySeekBarChangeListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [SeekBarOnSeekBarChangeListener],
            methods: {
                onProgressChanged: function (seekBar, progress, fromUser) {
                    if (fromUser) {
                        const newValue = self.progressToValue(progress);
                        self.value = newValue;
                        Java.scheduleOnMainThread(() => {
                            const valueView = self.view.valueView;
                            if (valueView) {
                                valueView.setText(String.$new(newValue.toString()));
                            }
                        });
                        self.emit("valueChanged", newValue);
                        if (self.handler)
                            setImmediate(() => self.handler(newValue));
                    }
                },
                onStartTrackingTouch: function (seekBar) {
                },
                onStopTrackingTouch: function (seekBar) {
                },
            },
        });
        seekBar.setOnSeekBarChangeListener(changeListener.$new());
    }
    onValueChange(handler) {
        this.handler = handler;
    }
    updateView() {
        if (!this.view) {
            Logger.instance.warn(`[Slider:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const seekBar = this.view.seekBar;
            const valueView = this.view.valueView;
            if (seekBar) {
                seekBar.setProgress(this.valueToProgress(this.value));
            }
            if (valueView) {
                const String = API.JString;
                valueView.setText(String.$new(this.value.toString()));
            }
        });
    }
    setLabel(label) {
        this.label = label;
        if (!this.view) {
            Logger.instance.warn(`[Slider:${this.id}] Cannot set label - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const labelView = this.view.labelView;
            if (labelView) {
                const String = API.JString;
                labelView.setText(String.$new(label));
            }
        });
    }
    setRange(min, max, step = 1) {
        this.min = min;
        this.max = max;
        this.step = step;
        this.value = this.clampToStep(this.value);
        if (!this.view) {
            Logger.instance.warn(`[Slider:${this.id}] Cannot set range - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            const seekBar = this.view.seekBar;
            if (seekBar) {
                seekBar.setMax(this.calculateSeekBarMax());
                seekBar.setProgress(this.valueToProgress(this.value));
            }
        });
        this.updateView();
    }
    calculateSeekBarMax() {
        return Math.round((this.max - this.min) / this.step);
    }
    valueToProgress(value) {
        return Math.round((value - this.min) / this.step);
    }
    progressToValue(progress) {
        const value = this.min + progress * this.step;
        return this.clampToStep(value);
    }
    clampToStep(value) {
        let clamped = Math.max(this.min, Math.min(this.max, value));
        if (this.step > 0) {
            const steps = Math.round((clamped - this.min) / this.step);
            clamped = this.min + steps * this.step;
        }
        return clamped;
    }
}
