import { Theme } from "./theme";
export type StyleRole = "overlay" | "card" | "category" | "row" | "text" | "caption" | "inputTrigger" | "primaryButton" | "dangerButton" | "headerBar" | "iconButton" | "textButton" | "dangerTextButton" | "divider" | "chip" | "dialog" | "inputField";
export declare function dp(ctx: any, v: number): number;
export declare function applyStyle(view: any, role: StyleRole, theme: Theme): void;
export declare function applyEditTextStyle(editText: any, theme: Theme): void;
