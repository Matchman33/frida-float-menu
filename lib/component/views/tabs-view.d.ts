import { Logger } from "../../logger.js";
import { Theme } from "../style/theme.js";
interface TabDefinition {
    id: string;
    label: string;
}
export declare class TabsView {
    private context;
    private parentView;
    private theme;
    tabContainer: any;
    tabs: Map<string, {
        label: string;
        container: any;
        root?: any;
        scrollView?: any;
        components: Set<string>;
    }>;
    activeTabId: any;
    tabView: any;
    menuPanelView: any;
    logger: Logger;
    initTabs: TabDefinition[];
    currentContentContainer: any;
    currentScrollView: any;
    private eventEmitter;
    tabScrollView: any;
    tabIndicatorView: any;
    private tabItemMap;
    constructor(context: any, theme: Theme, initTabs: TabDefinition[], activeTabId?: string);
    createTabView(parentView: any): void;
    private switchTab;
    private updateTabStyle;
    private updateTabIndicator;
    private refreshTabsUI;
    initializeTabs(): void;
    createTabContainer(): void;
}
export {};
