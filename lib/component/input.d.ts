import { UIComponent } from "./ui-components.js";
declare abstract class BaseInputButton extends UIComponent {
    protected title: string;
    protected hint: string;
    protected isShowDialog: boolean;
    protected buttonView: any;
    protected buttonLabelView: any;
    protected buttonIconView: any;
    constructor(id: string, title: string, hint: string);
    protected createBaseView(context: any): void;
    protected refreshButtonText(): void;
    protected abstract buildDisplayText(): string;
}
export declare class NumberInput extends BaseInputButton {
    private min;
    private max;
    private handler?;
    constructor(id: string, initialValue?: number, title?: string, hint?: string);
    protected buildDisplayText(): string;
    protected createView(context: any): void;
    protected updateView(): void;
    private showDialog;
    onValueChange(handler: (value: number) => void): void;
    private applyConstraints;
    setHint(hint: string): void;
    setConstraints(min: number | null, max: number | null): void;
    getNumber(): number;
    setNumber(value: number): void;
}
export declare class TextInput extends BaseInputButton {
    private handler?;
    constructor(id: string, initialValue?: string, title?: string, hint?: string);
    protected buildDisplayText(): string;
    protected createView(context: any): void;
    protected updateView(): void;
    protected emitValue(value: any): void;
    onValueChange(handler: (value: string) => void): void;
    private showDialog;
    setText(text: string): void;
}
export {};
