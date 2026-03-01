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
    overlayBg: 0xCC0B0F1A,
    cardBg: 0xE61A1F2E,
    text: 0xFFEAF0FF,
    subText: 0xFF9AA4B2,
    accent: 0xFF3B82F6,
    danger: 0xFFEF4444,
    divider: 0x22FFFFFF,
    controlBg: 0x33111827,
    controlStroke: 0x333B82F6,
  },
  radiusDp: { overlay: 16, card: 14, control: 12 },
  textSp: { title: 14, body: 13, caption: 11 },
};