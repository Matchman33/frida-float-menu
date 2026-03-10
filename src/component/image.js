"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
exports.ImageView = void 0;
const api_1 = require("../api");
const ui_components_1 = require("./ui-components");
class ImageView extends ui_components_1.UIComponent {
    constructor(id, source, width, height) {
        super(id);
        this.source = source;
        this.width = width;
        this.height = height;
        this.value = source;
    }
    createView(context) {
        const imageView = api_1.API.ImageView;
        const imageViewScaleType = api_1.API.ImageViewScaleType;
        const Color = api_1.API.Color;
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
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
                const Base64 = api_1.API.Base64;
                const BitmapFactory = api_1.API.BitmapFactory;
                const decoded = Base64.decode(source, Base64.DEFAULT.value);
                const bitmap = BitmapFactory.decodeByteArray(decoded, 0, decoded.length);
                this.view.setImageBitmap(bitmap);
            }
            catch (error) {
                console.error(`[Image:${this.id}] Failed to load image:`, error);
            }
        });
    }
    updateView() {
        if (!this.view) {
            console.warn(`[Image:${this.id}] Cannot update view - view not initialized`);
            return;
        }
        this.loadImage(this.source);
        this.updateSize();
    }
    updateSize() {
        const ViewGroupLayoutParams = api_1.API.ViewGroupLayoutParams;
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
exports.ImageView = ImageView;
ImageView.LayoutParamsEnum = {
    WRAP_CONTENT: api_1.API.ViewGroupLayoutParams.WRAP_CONTENT.value,
    MATCH_PARENT: api_1.API.ViewGroupLayoutParams.MATCH_PARENT.value,
};
