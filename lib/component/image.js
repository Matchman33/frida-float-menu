import Java from "frida-java-bridge";
import { API } from "../api.js";
import { Logger } from "../logger.js";
import { UIComponent } from "./ui-components.js";
export class ImageView extends UIComponent {
    constructor(id, source, width, height) {
        super(id);
        this.source = source;
        this.width = width;
        this.height = height;
        this.value = source;
    }
    createView(context) {
        const imageView = API.ImageView;
        const imageViewScaleType = API.ImageViewScaleType;
        const Color = API.Color;
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        this.view = imageView.$new(context);
        this.view.setScaleType(imageViewScaleType.FIT_CENTER.value);
        this.view.setBackgroundColor(Color.TRANSPARENT.value);
        const layoutParams = ViewGroupLayoutParams.$new(this.width, this.height);
        this.view.setLayoutParams(layoutParams);
        this.loadImage(this.source);
    }
    loadImage(source) {
        Java.scheduleOnMainThread(() => {
            try {
                const Base64 = API.Base64;
                const BitmapFactory = API.BitmapFactory;
                const decoded = Base64.decode(source, Base64.DEFAULT.value);
                const bitmap = BitmapFactory.decodeByteArray(decoded, 0, decoded.length);
                this.view.setImageBitmap(bitmap);
            }
            catch (error) {
                Logger.instance.error(`[Image:${this.id}] Failed to load image:`, error);
            }
        });
    }
    updateView() {
        if (!this.view) {
            Logger.instance.warn(`[Image:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        this.loadImage(this.source);
        this.updateSize();
    }
    updateSize() {
        const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
        const layoutParams = this.view.getLayoutParams();
        if (layoutParams) {
            layoutParams.width = this.width;
            layoutParams.height = this.height;
            this.view.setLayoutParams(layoutParams);
        }
        else {
            const newParams = ViewGroupLayoutParams.$new(this.width, this.height);
            this.view.setLayoutParams(newParams);
        }
    }
    setImage(source) {
        this.source = source;
        this.value = source;
        this.updateView();
    }
    setScaleType(scaleType) {
        if (this.view) {
            Java.scheduleOnMainThread(() => {
                this.view.setScaleType(scaleType);
            });
        }
    }
    setSize(width, height) {
        this.width = width;
        this.height = height;
        if (this.view) {
            Java.scheduleOnMainThread(() => {
                this.updateSize();
            });
        }
    }
}
ImageView.LayoutParamsEnum = {
    WRAP_CONTENT: API.ViewGroupLayoutParams.WRAP_CONTENT.value,
    MATCH_PARENT: API.ViewGroupLayoutParams.MATCH_PARENT.value,
};
