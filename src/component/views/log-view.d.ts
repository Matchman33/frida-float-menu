export declare class LogView {
    private context;
    private logDrawerPanel;
    isLogDrawerOpen: boolean;
    private _loggerUnsub;
    private logView;
    private logMaxLines;
    private theme;
    private parentView;
    private height;
    logScrollView: any;
    constructor(context: any, height: number, theme: any, logMaxLines?: number);
    private bindLoggerToLogViewOnce;
    private _logMaxLinesCache;
    private _logRing;
    private _logHead;
    private _logSize;
    private _logPending;
    private _logFlushScheduled;
    private addLogToView;
    createViewOnce(parentView: any): void;
    openLogDrawer(): void;
    closeLogDrawer(): void;
    private createLogView;
}
