export declare class LogViewWindow {
    private context;
    private windowManager;
    private theme;
    private logMaxLines;
    private windowRoot;
    private windowParams;
    private titleDragHandle;
    private logView;
    private isCreated;
    isLogWindowVisible: boolean;
    private _loggerUnsub;
    private _logMaxLinesCache;
    private _logRing;
    private _logHead;
    private _logSize;
    private _logPending;
    private _logFlushScheduled;
    constructor(context: any, theme: any, logMaxLines?: number);
    private bindLoggerToLogViewOnce;
    private addLogToView;
    createWindowOnce(): void;
    private bindDragForHeader;
    openLogWindow(): void;
    closeLogWindow(): void;
}
