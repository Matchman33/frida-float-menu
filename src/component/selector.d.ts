import { UIComponent } from "./ui-components";
export declare class Selector extends UIComponent {
    private items;
    private selectedIndex;
    private handler?;
    constructor(id: string, items: {
        lable: string;
        [key: string]: any;
    }[], selectedIndex?: number, handler?: (value: any) => {});
    getValue(): {
        lable: string;
        [key: string]: any;
    };
    protected createView(context: any): void;
    onValueChange(handler: (value: any) => {}): void;
    protected updateView(): void;
    setItems(items: {
        lable: string;
        [key: string]: any;
    }[]): void;
    getSelectedIndex(): number;
}
