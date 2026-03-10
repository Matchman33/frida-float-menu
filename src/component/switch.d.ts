import { UIComponent } from "./ui-components";
export declare class Switch extends UIComponent {
    private label;
    private handler?;
    private switchView;
    private labelView;
    onValueChange(handler: (vlaue: boolean) => void): void;
    constructor(id: string, label: string, initialValue?: boolean, handler?: (vlaue: boolean) => void);
    protected createView(context: any): void;
    protected updateView(): void;
    setLabel(label: string): void;
}
