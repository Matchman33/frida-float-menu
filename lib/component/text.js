import Java from "frida-java-bridge";
import { API } from "../api.js";
import { applyStyle } from "./style/style.js";
import { UIComponent } from "./ui-components.js";
export class TextView extends UIComponent {
    constructor(id, content, kind = "normal", size) {
        super(id);
        this.value = content;
        this.kind = kind;
        this.size = size;
    }
    createView(context) {
        const TextView = API.TextView;
        const Html = API.Html;
        const Gravity = API.Gravity;
        this.view = TextView.$new(context);
        applyStyle(this.view, this.kind === "note" ? "noteText" : "text", this.menu.options.theme);
        if (this.size != null) {
            this.view.setTextSize(2, this.size);
        }
        this.view.setGravity(Gravity.LEFT.value);
        this.view.setText(Html.fromHtml(this.value));
    }
    updateView() {
        if (!this.view)
            return;
        Java.scheduleOnMainThread(() => {
            const Html = API.Html;
            this.view.setText(Html.fromHtml(this.value));
        });
    }
    setText(content) {
        this.value = content;
        this.updateView();
    }
}
