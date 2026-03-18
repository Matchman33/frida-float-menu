import { Theme } from "../style/theme.js";
export interface HeaderViewOptions {
    context: any;
    parent: any;
    logMaxLines?: number;
    title: string;
    version: string;
}
export declare class HeaderView {
    private readonly theme;
    private headerDragView;
    constructor(theme: Theme);
    createView(options: HeaderViewOptions, callbacks: {
        onMinimize: () => void;
        onHide: () => void;
    }): any;
}
