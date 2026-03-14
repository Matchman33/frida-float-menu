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

    accentSoft?: number;
    accentStroke?: number;

    rowBg?: number;
    inputBg?: number;
    chipBg?: number;

    // 新增：更接近图里的信息块/说明块
    infoCardBg?: number;
    noteCardBg?: number;
    sectionText?: number;
    buttonText?: number;
  };
  radiusDp: { overlay: number; card: number; control: number };
  textSp: { title: number; body: number; caption: number };
};

export const DarkNeonTheme: Theme = {
  colors: {
    overlayBg: 0xcc0b0f1a | 0,
    cardBg: 0xe61a1f2e | 0,
    text: 0xffeaf0ff | 0,
    subText: 0xff9aa4b2 | 0,
    accent: 0xff2d6cff | 0,
    danger: 0xffef4444 | 0,
    divider: 0x22ffffff | 0,
    controlBg: 0x33111827 | 0,
    controlStroke: 0x333b82f6 | 0,

    accentSoft: 0x223b82f6 | 0,
    accentStroke: 0x663b82f6 | 0,

    rowBg: 0x1a111827 | 0,
    inputBg: 0x2a111827 | 0,
    chipBg: 0x22111827 | 0,

    infoCardBg: 0xdd1a2233 | 0,
    noteCardBg: 0xcc12213f | 0,
    sectionText: 0xffb7c2d6 | 0,
    buttonText: 0xffffffff | 0,
  },
  radiusDp: { overlay: 16, card: 14, control: 14 },
  textSp: { title: 14, body: 13, caption: 11 },
};