import { UIComponent } from "./ui-components";
export declare class Button extends UIComponent {
    private label;
    private handler?;
    private kind;
    constructor(id: string, label: string, kind?: "primary" | "danger", handler?: () => void);
    protected createView(context: any): void;
    protected updateView(): void;
    setLabel(label: string): void;
    onClick(handler: () => void): void;
}
