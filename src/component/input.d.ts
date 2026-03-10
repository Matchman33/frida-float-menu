import { UIComponent } from "./ui-components";
export declare class NumberInput extends UIComponent {
    private text;
    private hint;
    private min;
    private max;
    private handler?;
    private title;
    constructor(id: string, initialValue?: number, min?: number | null, max?: number | null, text?: string, hint?: string, title?: string);
    protected updateView(): void;
    getValue(): number;
    protected createView(context: any): void;
    private showDialog;
    setOnValueChange(handler: (value: number) => void): void;
    private applyConstraints;
    setHint(hint: string): void;
    setConstraints(min: number | null, max: number | null): void;
    getNumber(): number;
    setNumber(value: number): void;
}
export declare class TextInput extends UIComponent {
    private text;
    private hint;
    private handler?;
    private title;
    constructor(id: string, initialValue?: string, text?: string, hint?: string, title?: string);
    protected updateView(): void;
    protected createView(context: any): void;
    protected emitValue(value: any): void;
    setOnValueChange(handler: (value: string) => void): void;
    private showDialog;
    setText(text: string): void;
}
