import { EventEmitter } from './event-emitter.ts';

export abstract class UIComponent {
    protected emitter: EventEmitter = new EventEmitter();
    protected view: any; // Android View
    protected value: any;
    protected id: string;

    constructor(id: string) {
        this.id = id;
    }

    /**
     * Get the Android View associated with this component
     */
    public getView(): any {
        return this.view;
    }

    /**
     * Get current value of the component
     */
    public getValue(): any {
        return this.value;
    }

    /**
     * Set value and update UI
     */
    public setValue(value: any): void {
        this.value = value;
        this.updateView();
    }

    /**
     * Register event listener
     */
    public on(event: string, listener: (...args: any[]) => void): void {
        this.emitter.on(event, listener);
    }

    /**
     * Unregister event listener
     */
    public off(event: string, listener: (...args: any[]) => void): void {
        this.emitter.off(event, listener);
    }

    /**
     * Emit event
     */
    protected emit(event: string, ...args: any[]): void {
        this.emitter.emit(event, ...args);
    }

    /**
     * Abstract method to create the Android View
     */
    protected abstract createView(context: any): void;

    /**
     * Initialize the component with Android context
     */
    public init(context: any): void {
        this.createView(context);
    }

    /**
     * Abstract method to update the view when value changes
     */
    protected abstract updateView(): void;

    /**
     * Called when component is added to container
     */
    public attach(): void {
        // Override if needed
    }

    /**
     * Called when component is removed
     */
    public detach(): void {
        // Override if needed
    }
}

export class Button extends UIComponent {
    private label: string;
    private onClick: (() => void) | null = null;

    constructor(id: string, label: string) {
        super(id);
        this.label = label;
        this.value = null; // Buttons don't have a value
    }

    protected createView(context: any): void {
        const Button = Java.use('android.widget.Button');
        this.view = Button.$new(context);
        this.view.setText(this.label);
        const OnClickListener = Java.use('android.view.View$OnClickListener');
        const self = this;
        this.view.setOnClickListener(OnClickListener.$new({
            onClick: function(view: any) {
                self.emit('click');
                if (self.onClick) {
                    self.onClick();
                }
            }
        }));
    }

    protected updateView(): void {
        // Button value doesn't affect UI
    }

    /**
     * Set button label
     */
    public setLabel(label: string): void {
        this.label = label;
        Java.scheduleOnMainThread(() => {
            this.view.setText(label);
        });
    }

    /**
     * Set click handler
     */
    public setOnClick(handler: () => void): void {
        this.onClick = handler;
    }
}

export class Switch extends UIComponent {
    private label: string;

    constructor(id: string, label: string, initialValue: boolean = false) {
        super(id);
        this.label = label;
        this.value = initialValue;
    }

    protected createView(context: any): void {
        const Switch = Java.use('android.widget.Switch');
        this.view = Switch.$new(context);
        this.view.setText(this.label);
        this.view.setChecked(this.value);
        const CompoundButtonOnCheckedChangeListener = Java.use('android.widget.CompoundButton$OnCheckedChangeListener');
        const self = this;
        this.view.setOnCheckedChangeListener(CompoundButtonOnCheckedChangeListener.$new({
            onCheckedChanged: function(buttonView: any, isChecked: boolean) {
                self.value = isChecked;
                self.emit('valueChanged', isChecked);
            }
        }));
    }

    protected updateView(): void {
        Java.scheduleOnMainThread(() => {
            this.view.setChecked(this.value);
        });
    }

    /**
     * Set switch label
     */
    public setLabel(label: string): void {
        this.label = label;
        Java.scheduleOnMainThread(() => {
            this.view.setText(label);
        });
    }
}

export class Text extends UIComponent {
    private content: string;

    constructor(id: string, content: string) {
        super(id);
        this.content = content;
        this.value = content;
    }

    protected createView(context: any): void {
        const TextView = Java.use('android.widget.TextView');
        this.view = TextView.$new(context);
        this.view.setText(this.content);
    }

    protected updateView(): void {
        Java.scheduleOnMainThread(() => {
            this.view.setText(this.value);
        });
    }

    /**
     * Set text content
     */
    public setText(content: string): void {
        this.content = content;
        this.value = content;
        this.updateView();
    }
}

export class Selector extends UIComponent {
    private items: string[];
    private selectedIndex: number;

    constructor(id: string, items: string[], selectedIndex: number = 0) {
        super(id);
        this.items = items;
        this.selectedIndex = selectedIndex;
        this.value = items[selectedIndex];
    }

    protected createView(context: any): void {
        const Spinner = Java.use('android.widget.Spinner');
        this.view = Spinner.$new(context);
        const ArrayAdapter = Java.use('android.widget.ArrayAdapter');
        const adapter = ArrayAdapter.$new(context,
            Java.use('android.R').$new().layout.simple_spinner_item,
            Java.array('java.lang.CharSequence', this.items)
        );
        adapter.setDropDownViewResource(Java.use('android.R').$new().layout.simple_spinner_dropdown_item);
        this.view.setAdapter(adapter);
        this.view.setSelection(this.selectedIndex);
        const AdapterViewOnItemSelectedListener = Java.use('android.widget.AdapterView$OnItemSelectedListener');
        const self = this;
        this.view.setOnItemSelectedListener(AdapterViewOnItemSelectedListener.$new({
            onItemSelected: function(parent: any, view: any, position: number, id: number) {
                self.selectedIndex = position;
                self.value = self.items[position];
                self.emit('valueChanged', self.value);
            },
            onNothingSelected: function(parent: any) {
                // Do nothing
            }
        }));
    }

    protected updateView(): void {
        // Update selection based on value
        const index = this.items.indexOf(this.value);
        if (index !== -1) {
            Java.scheduleOnMainThread(() => {
                this.view.setSelection(index);
            });
        }
    }

    /**
     * Set selector items
     */
    public setItems(items: string[]): void {
        this.items = items;
        // Update adapter
        Java.scheduleOnMainThread(() => {
            const ArrayAdapter = Java.use('android.widget.ArrayAdapter');
            const context = this.view.getContext();
            const adapter = ArrayAdapter.$new(context,
                Java.use('android.R').$new().layout.simple_spinner_item,
                Java.array('java.lang.CharSequence', items)
            );
            adapter.setDropDownViewResource(Java.use('android.R').$new().layout.simple_spinner_dropdown_item);
            this.view.setAdapter(adapter);
        });
    }

    /**
     * Get selected index
     */
    public getSelectedIndex(): number {
        return this.selectedIndex;
    }
}