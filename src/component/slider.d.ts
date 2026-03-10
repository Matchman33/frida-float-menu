import { UIComponent } from "./ui-components";
export declare class Slider extends UIComponent {
    private min;
    private max;
    private step;
    private label;
    private handler?;
    constructor(id: string, label: string, min: number, max: number, initialValue?: number, step?: number, handler?: (value: number) => void);
    protected createView(context: any): void;
    onValueChange(handler: (value: number) => void): void;
    protected updateView(): void;
    setLabel(label: string): void;
    setRange(min: number, max: number, step?: number): void;
    private calculateSeekBarMax;
    private valueToProgress;
    private progressToValue;
    private clampToStep;
}
