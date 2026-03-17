import { UIComponent } from "./ui-components";
export declare class Selector extends UIComponent {
    private title;
    private items;
    private selectedIndex;
    private handler?;
    private context;
    private titleView;
    private valueView;
    constructor(id: string, title: string, items: {
        label: string;
        [key: string]: any;
    }[], selectedIndex?: number, handler?: (value: any) => void);
    getValue(): {
        label: string;
        [key: string]: any;
    };
    onValueChange(handler: (value: any) => void): void;
    protected createView(context: any): void;
    private getSelectedLabel;
    private getDisplayText;
    private showSelectDialog;
    private refreshUi;
    protected updateView(): void;
    setItems(items: {
        label: string;
        [key: string]: any;
    }[]): void;
    getSelectedIndex(): number;
    setTitle(title: string): void;
}
