import { UIComponent } from "./ui-components.js";
export declare class Category extends UIComponent {
    private label;
    private labelView;
    constructor(id: string, label: string);
    protected createView(context: any): void;
    protected updateView(): void;
    setLabel(label: string): void;
}
