import { UIComponent } from "./ui-components";
export declare class Category extends UIComponent {
    private label;
    constructor(id: string, label: string);
    protected createView(context: any): void;
    protected updateView(): void;
    setLabel(label: string): void;
}
