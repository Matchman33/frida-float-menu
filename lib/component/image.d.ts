import { UIComponent } from "./ui-components.js";
export declare class ImageView extends UIComponent {
    private source;
    private width;
    private height;
    static LayoutParamsEnum: {
        readonly WRAP_CONTENT: number;
        readonly MATCH_PARENT: number;
    };
    constructor(id: string, source: string | number, width: (typeof ImageView.LayoutParamsEnum)[keyof typeof ImageView.LayoutParamsEnum] | number, height: (typeof ImageView.LayoutParamsEnum)[keyof typeof ImageView.LayoutParamsEnum] | number);
    protected createView(context: any): void;
    private loadImage;
    protected updateView(): void;
    private updateSize;
    setImage(source: string | number): void;
    setScaleType(scaleType: any): void;
    setSize(width: number, height: number): void;
}
