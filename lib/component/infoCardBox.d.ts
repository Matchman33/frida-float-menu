import { UIComponent } from "./ui-components";
export declare class InfoCardText extends UIComponent {
    private content;
    private kind;
    private textView;
    private containerView;
    private size?;
    constructor(id: string, content: string, kind?: "normal" | "note", size?: number);
    protected createView(context: any): void;
    protected updateView(): void;
    setText(content: string): void;
    setKind(kind: "normal" | "note"): void;
}
