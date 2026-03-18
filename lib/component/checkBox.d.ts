import { UIComponent } from "./ui-components.js";
export interface CheckBoxOption {
    id: string;
    label: string;
    [key: string]: any;
}
export declare class CheckBoxGroup extends UIComponent {
    private optionsMap;
    private title;
    private changeHandler?;
    private valueChangeHandler?;
    private maxDisplayCount;
    private titleView;
    private valueView;
    private arrowView;
    private triggerRow;
    constructor(id: string, title: string, options: CheckBoxOption[], initialChecked?: string[]);
    onChangeHandler(handler: (value: CheckBoxOption[], item?: {
        id: string;
        checked: boolean;
    }) => void): void;
    onValueChangeHandler(handler: (value: CheckBoxOption[]) => void): void;
    setMaxDisplayCount(n: number): void;
    protected createView(context: any): void;
    private openMultiSelectDialog;
    protected updateView(): void;
    private getDisplayText;
    getCheckedValues(): CheckBoxOption[];
    setChecked(id: string, checked: boolean): void;
    setCheckedValues(checkedIds: string[]): void;
    getOptions(): CheckBoxOption[];
    setTitle(title: string): void;
}
