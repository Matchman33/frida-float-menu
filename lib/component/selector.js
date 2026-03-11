import { API } from "../api";
import { Logger } from "../logger";
import { UIComponent } from "./ui-components";
export class Selector extends UIComponent {
    constructor(id, items, selectedIndex = 0, handler) {
        super(id);
        this.items = items;
        this.selectedIndex = selectedIndex;
        this.value = items[selectedIndex];
        this.handler = handler;
    }
    getValue() {
        return this.value;
    }
    createView(context) {
        this.context = context;
        const Spinner = API.Spinner;
        const ArrayAdapter = API.ArrayAdapter;
        const String = API.JString;
        this.view = Spinner.$new(context);
        this.view.setBackgroundColor(0xff555555 | 0);
        const res = context.getResources();
        const itemLayout = res.getIdentifier("simple_spinner_item", "layout", "android");
        const dropLayout = res.getIdentifier("simple_spinner_dropdown_item", "layout", "android");
        const javaItems = this.items.map((item) => String.$new(item.lable));
        const adapter = ArrayAdapter.$new(context, itemLayout, Java.array("java.lang.String", javaItems));
        adapter.setDropDownViewResource(dropLayout);
        this.view.setAdapter(adapter);
        this.view.setSelection(this.selectedIndex);
        try {
            this.view.setPopupBackgroundResource(0xff333333 | 0);
        }
        catch (e) {
        }
        const AdapterViewOnItemSelectedListener = API.AdapterViewOnItemSelectedListener;
        const self = this;
        const itemSelectedListener = Java.registerClass({
            name: "com.frida.MyItemSelectedListener" +
                Date.now() +
                Math.random().toString(36).substring(6),
            implements: [AdapterViewOnItemSelectedListener],
            methods: {
                onItemSelected: function (parent, view, position, id) {
                    self.selectedIndex = position;
                    self.value = self.items[position];
                    self.emit("valueChanged", self.value);
                    if (self.handler)
                        setImmediate(() => self.handler(self.value));
                },
                onNothingSelected: function (parent) {
                },
            },
        });
        this.view.setOnItemSelectedListener(itemSelectedListener.$new());
    }
    onValueChange(handler) {
        this.handler = handler;
    }
    updateView() {
        if (!this.view) {
            Logger.instance.warn(`[Selector:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        const index = this.items.findIndex((value) => value.lable == this.value.lable);
        if (index !== -1) {
            Java.scheduleOnMainThread(() => {
                this.view.setSelection(index);
            });
        }
    }
    setItems(items) {
        this.items = items;
        if (!this.view) {
            Logger.instance.warn(`[Selector:${this.id}] Cannot set items - view not initialized`);
            return;
        }
        Java.scheduleOnMainThread(() => {
            try {
                const ArrayAdapter = API.ArrayAdapter;
                const String = API.JString;
                const javaItems = items.map((item) => String.$new(item.lable));
                const res = this.context.getResources();
                const itemLayout = res.getIdentifier("simple_spinner_item", "layout", "android");
                const dropLayout = res.getIdentifier("simple_spinner_dropdown_item", "layout", "android");
                const adapter = ArrayAdapter.$new(this.context, itemLayout, Java.array("java.lang.CharSequence", javaItems));
                adapter.setDropDownViewResource(dropLayout);
                this.view.setAdapter(adapter);
            }
            catch (error) {
                Logger.instance.error(`[Selector:${this.id}] Failed to set items:`, error);
            }
        });
    }
    getSelectedIndex() {
        return this.selectedIndex;
    }
}
