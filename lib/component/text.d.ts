import { UIComponent } from "./ui-components.js";
export declare class TextView extends UIComponent {
    private size?;
    private kind;
    constructor(id: string, content: string, kind?: "normal" | "note", size?: number);
    protected createView(context: any): void;
    protected updateView(): void;
    setText(content: string): void;
}
