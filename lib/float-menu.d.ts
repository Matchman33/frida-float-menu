import { UIComponent } from "./component/ui-components";
import { Logger } from "./logger";
import { Theme } from "./component/style/theme";
export interface TabDefinition {
    id: string;
    label: string;
}
export interface FloatMenuOptions {
    width?: number;
    height?: number;
    x?: number;
    y?: number;
    iconWidth?: number;
    iconHeight?: number;
    iconBase64?: string;
    logMaxLines?: number;
    theme?: Theme;
    title?: string;
    tabs?: TabDefinition[];
    activeTab?: string;
}
export declare class FloatMenu {
    options: FloatMenuOptions;
    private headerView;
    private headerComponent;
    private iconView;
    uiComponents: Map<string, UIComponent>;
    private pendingComponents;
    private eventEmitter;
    private isIconMode;
    private _context;
    private lastTouchX;
    private lastTouchY;
    private screenWidth;
    private screenHeight;
    private menuWindowParams;
    private iconWindowParams;
    private iconContainerWin;
    private menuContainerWin;
    private menuPanelView;
    logger: Logger;
    private tabsView;
    get context(): any;
    private _windowManager;
    get windowManager(): any;
    constructor(options?: FloatMenuOptions);
    private addDragListener;
    private createMenuContainerWindow;
    private updatePosition;
    private createIconWindow;
    toggleView(): void;
    show(): void;
    bindComponentEvents(component: UIComponent): void;
    private processPendingComponents;
    prepareComponentView(context: any, component: any): any;
    hide(): void;
    toast(msg: string, duration?: 0 | 1): void;
    addComponent(component: UIComponent, tabId?: string): void;
    removeComponent(id: string): void;
    getComponent<T extends UIComponent>(id: string): T | undefined;
    setComponentValue(id: string, value: any): void;
    on(event: string, callback: (...args: any[]) => void): void;
    off(event: string, callback: (...args: any[]) => void): void;
}
