import Java from "frida-java-bridge";
import { API } from "../api.js";
import { Logger } from "../logger.js";
import { UIComponent } from "./ui-components.js";

export class ImageView extends UIComponent {
  private source: string | number; // Base64 字符串或资源 ID
  private width: number;
  private height: number;

  public static LayoutParamsEnum = {
    WRAP_CONTENT: API.ViewGroupLayoutParams.WRAP_CONTENT.value as number,
    MATCH_PARENT: API.ViewGroupLayoutParams.MATCH_PARENT.value as number,
  } as const;

  /**
   * @param id 组件唯一标识
   * @param source 图片源：Base64 字符串
   * @param width 宽度（像素），默认 WRAP_CONTENT
   * @param height 高度（像素），默认 WRAP_CONTENT
   */
  constructor(
    id: string,
    source: string | number,
    width:
      | (typeof ImageView.LayoutParamsEnum)[keyof typeof ImageView.LayoutParamsEnum]
      | number,
    height:
      | (typeof ImageView.LayoutParamsEnum)[keyof typeof ImageView.LayoutParamsEnum]
      | number,
  ) {
    super(id);
    this.source = source;
    this.width = width;
    this.height = height;
    this.value = source; // 可选，存储源值
  }

  protected createView(context: any): void {
    const imageView = API.ImageView;
    const imageViewScaleType = API.ImageViewScaleType;
    const Color = API.Color;
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;

    this.view = imageView.$new(context);
    this.view.setScaleType(imageViewScaleType.FIT_CENTER.value);
    this.view.setBackgroundColor(Color.TRANSPARENT.value);

    // 设置自定义尺寸
    const layoutParams = ViewGroupLayoutParams.$new(this.width, this.height);
    this.view.setLayoutParams(layoutParams);

    this.loadImage(this.source);
  }

  private loadImage(source: string | number): void {
    Java.scheduleOnMainThread(() => {
      try {
        const Base64 = API.Base64;
        const BitmapFactory = API.BitmapFactory;
        const decoded = Base64.decode(source, Base64.DEFAULT.value);
        const bitmap = BitmapFactory.decodeByteArray(
          decoded,
          0,
          decoded.length,
        );
        this.view.setImageBitmap(bitmap);
      } catch (error) {
        Logger.instance.error(`[Image:${this.id}] Failed to load image:`, error);
      }
    });
  }

  protected updateView(): void {
    if (!this.view) {
      Logger.instance.warn(
        `[Image:${this.id}] Cannot update view - view not initialized`,
      );
      return;
    }
    // 更新图片源
    this.loadImage(this.source);
    // 更新尺寸
    this.updateSize();
  }

  private updateSize(): void {
    const ViewGroupLayoutParams = API.ViewGroupLayoutParams;
    const layoutParams = this.view.getLayoutParams();
    if (layoutParams) {
      layoutParams.width = this.width;
      layoutParams.height = this.height;
      this.view.setLayoutParams(layoutParams);
    } else {
      const newParams = ViewGroupLayoutParams.$new(this.width, this.height);
      this.view.setLayoutParams(newParams);
    }
  }

  /**
   * 设置新的图片源
   * @param source Base64 字符串或资源 ID
   */
  public setImage(source: string | number): void {
    this.source = source;
    this.value = source;
    this.updateView();
  }

  /**
   * 设置图片缩放类型
   */
  public setScaleType(scaleType: any): void {
    if (this.view) {
      Java.scheduleOnMainThread(() => {
        this.view.setScaleType(scaleType);
      });
    }
  }

  /**
   * 设置图片尺寸
   * @param width 宽度（像素）或 WRAP_CONTENT/MATCH_PARENT 常量
   * @param height 高度（像素）或 WRAP_CONTENT/MATCH_PARENT 常量
   */
  public setSize(width: number, height: number): void {
    this.width = width;
    this.height = height;
    if (this.view) {
      Java.scheduleOnMainThread(() => {
        this.updateSize();
      });
    }
  }
}
