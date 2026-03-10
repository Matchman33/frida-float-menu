"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.Category = void 0;
const api_1 = require("../api");
const style_1 = require("./style/style");
const ui_components_1 = require("./ui-components");
class Category extends ui_components_1.UIComponent {
    constructor(id, label) {
        super(id);
        this.label = label;
        this.value = label;
    }
    createView(context) {
        const TextView = api_1.API.TextView;
        const String = api_1.API.JString;
        const LinearLayoutParams = api_1.API.LinearLayoutParams;
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
        this.view = TextView.$new(context);
        this.view.setText(String.$new(this.label));
        (0, style_1.applyStyle)(this.view, "category", this.menu.options.theme);
        this.view.setLayoutParams(LinearLayoutParams.$new(ViewGroupLayoutParams.MATCH_PARENT.value, ViewGroupLayoutParams.WRAP_CONTENT.value));
    }
    updateView() {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => {
            const String = api_1.API.JString;
            this.view.setText(String.$new(this.value));
        });
    }
    setLabel(label) {
        this.label = label;
        this.value = label;
        this.updateView();
    }
}
exports.Category = Category;
