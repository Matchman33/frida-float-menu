import { EventEmitter } from './event-emitter.ts';
import { UIComponent, Button, Switch, Text, Selector } from './ui-components.ts';
import { Logger, LogLevel } from './logger.ts';

export interface FloatMenuOptions {
    width?: number;
    height?: number;
    x?: number;
    y?: number;
    iconBase64?: string; // base64 encoded icon for floating window
    showLogs?: boolean; // whether to show log panel
    logMaxLines?: number;
}

export class FloatMenu {
    private options: FloatMenuOptions;
    private windowManager: any; // Android WindowManager
    private windowParams: any; // WindowManager.LayoutParams
    private containerView: any; // LinearLayout or RelativeLayout
    private uiComponents: Map<string, UIComponent> = new Map();
    private logView: any; // TextView or ListView for logs
    private eventEmitter: EventEmitter = new EventEmitter();
    private logger: Logger;
    private isShown: boolean = false;

    constructor(options: FloatMenuOptions = {}) {
        this.options = {
            width: 300,
            height: 400,
            x: 100,
            y: 100,
            showLogs: false,
            logMaxLines: 100,
            ...options
        };
        this.logger = new Logger(this.options.showLogs ? 'debug' : 'none');
        if (this.options.showLogs) {
            this.logger.on('log', (level: LogLevel, message: string) => {
                this.addLogToView(level, message);
            });
        }
        this.logger.info('FloatMenu initialized');
    }

    /**
     * Create and show the floating window
     */
    public show(): void {
        Java.scheduleOnMainThread(() => {
            try {
                // Get WindowManager
                const context = Java.use('android.app.ActivityThread').currentApplication().getApplicationContext();
                this.windowManager = context.getSystemService('window');

                // Create LayoutParams
                const LayoutParams = Java.use('android.view.WindowManager$LayoutParams');
                this.windowParams = LayoutParams.$new();
                this.windowParams.type = LayoutParams.TYPE_APPLICATION_OVERLAY;
                this.windowParams.flags = LayoutParams.FLAG_NOT_FOCUSABLE | LayoutParams.FLAG_NOT_TOUCH_MODAL;
                this.windowParams.format = 1; // PixelFormat.TRANSLUCENT
                this.windowParams.width = this.options.width;
                this.windowParams.height = this.options.height;
                this.windowParams.x = this.options.x;
                this.windowParams.y = this.options.y;

                // Create container layout
                const LinearLayout = Java.use('android.widget.LinearLayout');
                this.containerView = LinearLayout.$new(context);
                this.containerView.setOrientation(LinearLayout.VERTICAL);
                const LayoutParamsClass = Java.use('android.view.ViewGroup$LayoutParams');
                this.containerView.setLayoutParams(LayoutParamsClass.$new(this.options.width, this.options.height));

                // Set icon if provided
                if (this.options.iconBase64) {
                    this.setIcon(this.options.iconBase64);
                }

                // Add log view if enabled
                if (this.options.showLogs) {
                    this.createLogView(context);
                }

                // Add container to window
                this.windowManager.addView(this.containerView, this.windowParams);
                this.isShown = true;
                this.logger.info('Floating window shown');
            } catch (error) {
                this.logger.error('Failed to show floating window: ' + error);
            }
        });
    }

    /**
     * Hide and destroy the floating window
     */
    public hide(): void {
        if (!this.isShown) return;
        Java.scheduleOnMainThread(() => {
            try {
                this.windowManager.removeView(this.containerView);
                this.isShown = false;
                this.logger.info('Floating window hidden');
            } catch (error) {
                this.logger.error('Failed to hide floating window: ' + error);
            }
        });
    }

    /**
     * Add a UI component to the floating window
     * @param id Unique identifier for the component
     * @param component UI component instance
     */
    public addComponent(id: string, component: UIComponent): void {
        if (!this.containerView) {
            this.logger.error('Cannot add component before floating window is shown');
            return;
        }
        this.uiComponents.set(id, component);
        Java.scheduleOnMainThread(() => {
            const context = this.containerView.getContext();
            component.init(context);
            const view = component.getView();
            this.containerView.addView(view);
            // Bind events
            component.on('valueChanged', (value: any) => {
                this.eventEmitter.emit('component:' + id + ':valueChanged', value);
            });
            component.on('action', (data: any) => {
                this.eventEmitter.emit('component:' + id + ':action', data);
            });
            component.on('click', (data: any) => {
                this.eventEmitter.emit('component:' + id + ':action', data);
            });
        });
        this.logger.debug(`Component ${id} added`);
    }

    /**
     * Remove a UI component
     */
    public removeComponent(id: string): void {
        const component = this.uiComponents.get(id);
        if (!component) return;
        Java.scheduleOnMainThread(() => {
            this.containerView.removeView(component.getView());
        });
        this.uiComponents.delete(id);
        this.logger.debug(`Component ${id} removed`);
    }

    /**
     * Get a component by id
     */
    public getComponent<T extends UIComponent>(id: string): T | undefined {
        return this.uiComponents.get(id) as T;
    }

    /**
     * Update component value from JS
     */
    public setComponentValue(id: string, value: any): void {
        const component = this.uiComponents.get(id);
        if (component) {
            component.setValue(value);
        }
    }

    /**
     * Register event listener for component
     */
    public on(event: string, callback: (...args: any[]) => void): void {
        this.eventEmitter.on(event, callback);
    }

    /**
     * Unregister event listener
     */
    public off(event: string, callback: (...args: any[]) => void): void {
        this.eventEmitter.off(event, callback);
    }

    /**
     * Update floating window position
     */
    public setPosition(x: number, y: number): void {
        if (!this.isShown) return;
        Java.scheduleOnMainThread(() => {
            this.windowParams.x = x;
            this.windowParams.y = y;
            this.windowManager.updateViewLayout(this.containerView, this.windowParams);
        });
    }

    /**
     * Update floating window size
     */
    public setSize(width: number, height: number): void {
        if (!this.isShown) return;
        Java.scheduleOnMainThread(() => {
            this.windowParams.width = width;
            this.windowParams.height = height;
            this.windowManager.updateViewLayout(this.containerView, this.windowParams);
            // Also update container layout params
            const layoutParams = this.containerView.getLayoutParams();
            layoutParams.width = width;
            layoutParams.height = height;
            this.containerView.setLayoutParams(layoutParams);
        });
    }

    /**
     * Set icon from base64 string
     */
    private setIcon(base64: string): void {
        Java.scheduleOnMainThread(() => {
            try {
                const context = this.containerView.getContext();
                const BitmapFactory = Java.use('android.graphics.BitmapFactory');
                const Base64 = Java.use('android.util.Base64');
                const decoded = Base64.decode(base64, Base64.DEFAULT);
                const bitmap = BitmapFactory.decodeByteArray(decoded, 0, decoded.length);
                // Create ImageView and set bitmap
                const ImageView = Java.use('android.widget.ImageView');
                const iconView = ImageView.$new(context);
                iconView.setImageBitmap(bitmap);
                const LinearLayoutParams = Java.use('android.widget.LinearLayout$LayoutParams');
                iconView.setLayoutParams(LinearLayoutParams.$new(50, 50));
                this.containerView.addView(iconView, 0);
            } catch (error) {
                this.logger.error('Failed to set icon: ' + error);
            }
        });
    }

    /**
     * Create log view (TextView) for displaying logs
     */
    private createLogView(context: any): void {
        const TextView = Java.use('android.widget.TextView');
        this.logView = TextView.$new(context);
        const LinearLayoutParams = Java.use('android.widget.LinearLayout$LayoutParams');
        this.logView.setLayoutParams(LinearLayoutParams.$new(this.options.width, 200));
        this.logView.setTextSize(10);
        this.logView.setBackgroundColor(0x80000000); // semi-transparent black
        this.logView.setTextColor(0xFFFFFFFF);
        this.logView.setMaxLines(this.options.logMaxLines);
        this.logView.setVerticalScrollBarEnabled(true);
        this.containerView.addView(this.logView);
    }

    /**
     * Add log message to log view
     */
    private addLogToView(level: LogLevel, message: string): void {
        const logView = this.logView;
        if (!logView) return;
        const logMaxLines = this.options.logMaxLines || 100;
        Java.scheduleOnMainThread(() => {
            const currentText = logView.getText().toString();
            const newLine = `[${level}] ${message}`;
            const lines = currentText.split('\n');
            if (lines.length >= logMaxLines) {
                lines.shift();
            }
            lines.push(newLine);
            logView.setText(lines.join('\n'));
        });
    }

    /**
     * Clear log view
     */
    public clearLogs(): void {
        if (!this.logView) return;
        Java.scheduleOnMainThread(() => {
            this.logView.setText('');
        });
    }
}