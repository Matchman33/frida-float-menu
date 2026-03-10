import { UIComponent } from "./ui-components";
export declare class Collapsible extends UIComponent {
    private title;
    private expanded;
    private contentContainer;
    private arrowView;
    pendingChildren: UIComponent[];
    constructor(id: string, title: string, expanded?: boolean);
    protected createView(context: any): void;
    protected updateView(): void;
    toggle(): void;
    expand(): void;
    collapse(): void;
    setTitle(title: string): void;
    addChild(component: UIComponent): void;
    addChildren(components: UIComponent[]): void;
    removeChildView(view: any): void;
    clearChildren(): void;
}
