import { UIComponent } from "./ui-components";
export interface CheckBoxOption {
    id: string;
    label: string;
    [key: string]: any;
}
export declare class CheckBoxGroup extends UIComponent {
    private optionsMap;
    private changeHandler?;
    private valueChangeHandler?;
    private triggerText;
    private maxDisplayCount;
    constructor(id: string, options: CheckBoxOption[], initialChecked?: string[], _columns?: number);
    onChangeHandler(handler: (value: CheckBoxOption[], item?: {
        id: string;
        checked: boolean;
    }) => void): void;
    onValueChangeHandler(handler: (value: CheckBoxOption[]) => void): void;
    setMaxDisplayCount(n: number): void;
    protected createView(context: any): void;
    private openMultiSelectDialog;
    protected updateView(): void;
    private buildDisplayText;
    getCheckedValues(): CheckBoxOption[];
    setChecked(id: string, checked: boolean): void;
    setCheckedValues(checkedIds: string[]): void;
    getOptions(): CheckBoxOption[];
}
