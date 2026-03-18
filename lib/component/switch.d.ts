import { UIComponent } from "./ui-components.js";
export declare class Switch extends UIComponent {
    private label;
    private handler?;
    private labelView;
    private switchView;
    onValueChange(handler: (value: boolean) => void): void;
    constructor(id: string, label: string, initialValue?: boolean, handler?: (value: boolean) => void);
    protected createView(context: any): void;
    protected updateView(): void;
    setLabel(label: string): void;
}
