export type Theme = {
  colors: {
    overlayBg: number;
    cardBg: number;
    text: number;
    subText: number;
    accent: number;
    danger: number;
    divider: number;
    controlBg: number;
    controlStroke: number;
  };
  radiusDp: { overlay: number; card: number; control: number };
  textSp: { title: number; body: number; caption: number };
};

// Dark translucent overlay + neon accent (good for game overlay menus)
export const DarkNeonTheme: Theme = {
  colors: {
    overlayBg: 0xcc0b0f1a | 0,
    cardBg: 0xe61a1f2e | 0,
    text: 0xffeaf0ff | 0,
    subText: 0xff9aa4b2 | 0,
    accent: 0xff3b82f6 | 0,
    danger: 0xffef4444 | 0,
    divider: 0x22ffffff | 0,
    controlBg: 0x33111827 | 0,
    controlStroke: 0x333b82f6 | 0,
  },
  radiusDp: { overlay: 16, card: 14, control: 12 },
  textSp: { title: 14, body: 13, caption: 11 },
};
