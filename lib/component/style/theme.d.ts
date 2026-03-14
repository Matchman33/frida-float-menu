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
        infoCardBg?: number;
        noteCardBg?: number;
        sectionText?: number;
        buttonText?: number;
    };
    radiusDp: {
        overlay: number;
        card: number;
        control: number;
    };
    textSp: {
        title: number;
        body: number;
        caption: number;
    };
};
export declare const DarkNeonTheme: Theme;
