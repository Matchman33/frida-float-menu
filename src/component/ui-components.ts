import { EventEmitter } from "../event-emitter";

export abstract class UIComponent {
  protected emitter: EventEmitter = new EventEmitter();
  // 必须实例化view
  protected view: any; // Android View
  protected value: any;
  protected id: string;

  constructor(id: string) {
    this.id = id;
  }
  // 可选：给后续写通用样式留口子
  public apply(role: any, theme: any) {
    if (!this.view) return;
    const { applyStyle } = require("../style/style"); // 也可以正常 import
    Java.scheduleOnMainThread(() => applyStyle(this.view, role, theme));
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

  public getId(): string {
    return this.id;
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
