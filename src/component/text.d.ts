import { UIComponent } from "./ui-components";
export declare class TextView extends UIComponent {
    private content;
    private size;
    constructor(id: string, content: string, size?: number);
    protected createView(context: any): void;
    protected updateView(): void;
    setText(content: string): void;
}
