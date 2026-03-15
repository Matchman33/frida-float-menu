import { ConstantConfig } from "./constant-config";

/**
 * 真实坐标转换为逻辑坐标，以左上角为原点转换为屏幕中心为原点
 * @param wx
 * @param wy
 * @returns
 */
export function windowToLogical(
  wx: number,
  wy: number,
  w: number,
  h: number,
) {
  return {
    x: Math.round(wx + (ConstantConfig.screenWidth - w) / 2),
    y: Math.round(wy + (ConstantConfig.screenHeight - h) / 2),
  };
}

/**
 * 逻辑坐标转换为真实坐标，以左上角为原点转换为屏幕中心为原点
 * @param lx
 * @param ly
 * @returns
 */
export function logicalToWindow(
  lx: number,
  ly: number,
  w: number,
  h: number,
) {
  return {
    x: Math.round(lx - (ConstantConfig.screenWidth - w) / 2),
    y: Math.round(ly - (ConstantConfig.screenHeight - h) / 2),
  };
}
