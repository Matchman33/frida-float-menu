import { Theme } from "./theme.js";
export type StyleRole = "overlay" | "card" | "category" | "row" | "fieldLabel" | "selectValue" | "text" | "caption" | "noteText" | "infoCard" | "noteCard" | "inputButton" | "inputTrigger" | "primaryButton" | "dangerButton" | "headerBar" | "iconButton" | "textButton" | "dangerTextButton" | "divider" | "chip" | "dialog" | "inputField";
export declare function dp(ctx: any, v: number): number;
export declare function applyStyle(view: any, role: StyleRole, theme: Theme): void;
