import { ConstantConfig } from "./constant-config.js";
export function windowToLogical(wx, wy, w, h) {
    return {
        x: Math.round(wx + (ConstantConfig.screenWidth - w) / 2),
        y: Math.round(wy + (ConstantConfig.screenHeight - h) / 2),
    };
}
export function logicalToWindow(lx, ly, w, h) {
    return {
        x: Math.round(lx - (ConstantConfig.screenWidth - w) / 2),
        y: Math.round(ly - (ConstantConfig.screenHeight - h) / 2),
    };
}
