"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.TextView = void 0;
const api_1 = require("../api");
const style_1 = require("./style/style");
const ui_components_1 = require("./ui-components");
class TextView extends ui_components_1.UIComponent {
    constructor(id, content, size = 16) {
        super(id);
        this.content = content;
        this.value = content;
        this.size = size;
    }
    createView(context) {
        const TextView = api_1.API.TextView;
        const Html = api_1.API.Html;
        this.view = TextView.$new(context);
        (0, style_1.applyStyle)(this.view, "text", this.menu.options.theme);
        this.view.setTextSize(this.size);
        this.view.setText(Html.fromHtml(this.content));
    }
    updateView() {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => {
            const Html = api_1.API.Html;
            this.view.setText(Html.fromHtml(this.value));
        });
    }
    setText(content) {
        this.content = content;
        this.value = content;
        this.updateView();
    }
}
exports.TextView = TextView;
