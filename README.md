# Frida Overlay Menu - Android 悬浮窗 UI 库

一个为 Frida 逆向工程设计的 TypeScript 库，用于在 Android 设备上创建交互式悬浮窗口。支持多种 UI 组件（按钮、开关、文本、选择器等），可以轻松地从 JavaScript 控制。

## ✨ 特性

- 📱 创建 Android 悬浮窗，使用系统 `WindowManager`
- 🎨 丰富的 UI 组件：Button、Switch、Text、Selector、Slider、Collapsible、Category、TextInput、NumberInput、CheckBoxGroup、ImageView
- 🔄 双向数据绑定：JavaScript 变量与 UI 状态同步
- 📡 完整的事件系统：组件交互、值变更等
- 💻 通过编程方式更新 UI 组件
- 📋 可选的日志面板，显示运行时日志（可禁用以提升性能）
- 🖼️ 支持通过 base64 编码图片设置窗口图标
- 📑 支持多标签页管理，更好地组织 UI
- 🎯 模块化、可扩展的架构
- 📝 完整的 TypeScript 类型定义

## 使用截图
<img src="./基础组件.jpg" alt="表单组件" width="200">
<img src="./布局组件.jpg" alt="布局组件" width="200">
<img src="./基础组件.jpg" alt="基础组件" width="200">
<img src="./日志窗口.jpg" alt="日志窗口" width="200">
<img src="./选择组件.jpg" alt="选择组件" width="200">

## 📋 环境要求

- Frida（已测试 Android 15和16 平台）
- 目标 Android 应用需要悬浮窗权限（API 26+ 需要权限 `TYPE_APPLICATION_OVERLAY`）
- frida-compile 用于 TypeScript 编译（已包含在开发依赖中）

## 🚀 安装

### 在你的 Frida 项目中使用

1. 将 `src/` 目录复制到你的项目
2. 在 TypeScript 文件中导入库：

```typescript
import { FloatMenu, Button, Switch, Text } from './path/to/src/index';
```

## 📖 快速开始

### 1. 创建 TypeScript 文件 (`my-script.ts`)

```typescript
import { FloatMenu, Button, Switch, Text, Selector } from './src/index';
import { ConstantConfig } from "./src/constant-config";

// 使用ConstantConfig.isDev来设置当前是否为调试环境，此属性会影响日志打印级别。非dev环境不会打印debug日志。默认为false。
ConstantConfig.isDev = true;

Java.perform(() => {
    // 创建悬浮菜单
    const menu = new FloatMenu({
        width: 1200,
        height: 900,
        title: "我的菜单"
    });

    menu.show();

    // 添加按钮组件
    const button = new Button('myButton', '点击我', 'primary');
    button.onClick(() => {
        console.log('按钮被点击了！');
        menu.toast('按钮被点击！');
    });
    menu.addComponent(button);

    // 添加开关组件
    const switchComp = new Switch('mySwitch', '启用功能', false);
    switchComp.on('valueChanged', (value: boolean) => {
        console.log('开关状态:', value);
    });
    menu.addComponent(switchComp);
});
```

### 2. 使用 frida-compile 编译

```bash
frida-compile my-script.ts -o my-script-compiled.js -c
```

### 3. 注入到目标应用

```bash
frida -U -f com.example.app -l my-script-compiled.js
```

## 📚 组件介绍

本项目提供了丰富的 UI 组件，全部在 `example.ts` 中有详细的使用示例。以下是按功能分类的组件说明：

### 🎯 基础组件 (Basic Components)

#### 1. Text - 文本组件
显示静态或动态文本，支持 HTML 富文本格式。

```typescript
const text = new Text('myText', '这是普通文本');
const richText = new Text('richText', 'HTML <b>富文本</b> 支持');
menu.addComponent(text);
menu.addComponent(richText);
```

#### 2. Button - 按钮组件
支持两种样式：主要按钮（primary）和危险按钮（danger）。

```typescript
const primaryButton = new Button('btn1', '主要按钮', 'primary');
const dangerButton = new Button('btn2', '危险操作', 'danger');

primaryButton.onClick(() => {
    menu.toast('主要按钮被点击！');
});
menu.addComponent(primaryButton);
menu.addComponent(dangerButton);
```

#### 3. Category - 分类标题
用于组织和分组 UI 组件的分隔标题。

```typescript
const category = new Category('category1', '基础组件');
menu.addComponent(category);
```

### 📝 表单组件 (Form Components)

#### 4. TextInput - 文本输入框
单行文本输入，带有弹窗输入界面。

```typescript
const usernameInput = new TextInput(
    'username',
    '',        // 初始值
    '用户名：', // 按钮文本
    '请输入用户名', // 提示文本
);

usernameInput.setonClick((value: string) => {
    console.log('用户名:', value);
    menu.toast(`用户名设置为: ${value}`);
});
menu.addComponent(usernameInput);
```

#### 5. NumberInput - 数字输入框
数值输入。

```typescript
const ageInput = new NumberInput(
    'age',
    25,         // 初始值
    '年龄：',    // 按钮文本
    '请输入年龄', // 提示文本
    '输入年龄'    // 对话框标题
);

ageInput.onValueChange((value: number) => {
    console.log('年龄:', value);
    // 根据年龄显示不同分类
    let category = value < 18 ? "未成年" : "成年人";
    menu.toast(`年龄段: ${category}`);
});
menu.addComponent(ageInput);
```

#### 6. Switch - 开关组件
简单的二选一开关。

```typescript
const soundSwitch = new Switch('sound', '音效', false);
soundSwitch.on('valueChanged', (value: boolean) => {
    console.log('音效开关:', value);
    menu.toast(`音效已${value ? '开启' : '关闭'}`);
});
menu.addComponent(soundSwitch);
```

#### 7. CheckBoxGroup - 多选框组
支持多选的复选框组件。

```typescript
const hobbiesGroup = new CheckBoxGroup(
    'hobbies',
    [
        { id: 'reading', label: '阅读' },
        { id: 'music', label: '音乐' },
        { id: 'sports', label: '运动' },
        { id: 'travel', label: '旅行' },
    ],
    ['reading']  // 初始选中的项
);

hobbiesGroup.on('valueChanged', (values: any[]) => {
    console.log('选中的爱好:', values);
    const labels = values.map(v => v.label).join(', ');
    menu.toast(`选中的爱好: ${labels}`);
});
menu.addComponent(hobbiesGroup);
```

### 🔘 选择组件 (Selection Components)

#### 8. Selector - 下拉选择器
从多个选项中选择一个，支持自定义数据对象。

```typescript
const citySelector = new Selector(
    'city',
    [
        { lable: '北京', code: 'BJ' },
        { lable: '上海', code: 'SH' },
        { lable: '广州', code: 'GZ' },
        { lable: '深圳', code: 'SZ' },
    ],
    0  // 默认选中第一个
);

citySelector.on('valueChanged', (value: any) => {
    console.log('选择的城市:', value.lable, value.code);
    menu.toast(`当前城市: ${value.lable}`);
});
menu.addComponent(citySelector);
```

#### 9. Slider - 滑块组件
数值范围选择，支持自定义步进。

```typescript
const volumeSlider = new Slider(
    'volume',
    '音量控制',
    0,    // 最小值
    100,  // 最大值
    50,   // 初始值
    1     // 步进
);

volumeSlider.on('valueChanged', (value: number) => {
    console.log('音量:', value);
    menu.toast(`音量: ${value}%`);
});
menu.addComponent(volumeSlider);
```

### 📦 布局组件 (Layout Components)

#### 10. Collapsible - 可折叠面板
可以展开和折叠的面板，支持嵌套子组件。

```typescript
const settingsCollapsible = new Collapsible(
    'settings',
    '用户设置',
    true  // 初始展开状态
);

// 添加子组件到折叠面板
const usernameInput = new TextInput('username', 'admin', '用户名', '请输入用户名');
const roleSelector = new Selector('role', [
    { lable: '管理员', role: 'admin' },
    { lable: '普通用户', role: 'user' }
], 0);

settingsCollapsible.addChildren([
    usernameInput,
    roleSelector
]);

menu.addComponent(settingsCollapsible);
```

#### 11. ImageView - 图片组件
显示 base64 编码的图片。

```typescript
import { iconBase64 } from './icon';

const imageView = new ImageView(
    'logo',
    iconBase64,  // base64 编码的图片
    400,         // 宽度
    400          // 高度
);
menu.addComponent(imageView);
```

### 🔄 交互演示 (Interactive Demo)

在 `example.ts` 中展示了组件之间的交互和联动效果：

1. **用户评分系统**：包含文本输入、滑块选择、多选标签、评论和提交按钮
2. **购物车功能**：商品选择、数量调整、运费计算、总价自动更新

这些示例展示了如何：
- 组件之间相互影响
- 获取其他组件的值
- 动态更新 UI 显示
- 处理复杂的用户交互

## 🎛️ 多标签页支持

FloatMenu 支持创建多个标签页来更好地组织 UI 组件：

```typescript
const menu = new FloatMenu({
    width: 1200,
    height: 1400,
    title: "综合测试用例",
    tabs: [
        { id: "basic", label: "基础组件" },
        { id: "form", label: "表单组件" },
        { id: "selection", label: "选择组件" },
        { id: "layout", label: "布局组件" },
        { id: "interactive", label: "交互演示" },
    ],
    activeTab: "basic"  // 默认显示的标签页
});

menu.show();

// 将组件添加到特定标签页
const button = new Button("btn1", "点击我");
menu.addComponent(button, "basic");  // 添加到"基础组件"标签页

const input = new TextInput("name", "", "姓名", "请输入姓名", "输入姓名");
menu.addComponent(input, "form");  // 添加到"表单组件"标签页
```

## 📡 API 参考

### FloatMenu - 主类

创建和管理悬浮窗口的主类。

```typescript
interface TabDefinition {
    id: string;      // 标签页唯一标识符
    label: string;   // 标签页显示的标题
}

interface FloatMenuOptions {
    width?: number;           // 窗口宽度（默认：1000）
    height?: number;          // 窗口高度（默认：900）
    x?: number;              // X 坐标（默认：0）
    y?: number;              // Y 坐标（默认：0）
    iconWidth?: number;       // 图标宽度（默认：200）
    iconHeight?: number;      // 图标高度（默认：200）
    iconBase64?: string;      // Base64 编码的图标图片（可选）
    logMaxLines?: number;     // 日志面板最大行数（默认：100）
    theme?: Theme;            // 主题设置
    title?: string;           // 主标题文本（默认："Frida Float Menu"）
    tabs?: TabDefinition[];   // 标签页定义（可选）
    activeTab?: string;       // 初始激活的标签页 ID（默认：第一个标签页或 "default"）
}

class FloatMenu {
    constructor(options?: FloatMenuOptions);
    show(): void;  // 显示窗口
    hide(): void;  // 隐藏窗口
    addComponent(component: UIComponent, tabId?: string): void;  // 添加组件
    removeComponent(id: string): void;  // 移除组件
    getComponent<T extends UIComponent>(id: string): T | undefined;  // 获取组件
    setComponentValue(id: string, value: any): void;  // 更新组件值
    on(event: string, callback: (...args: any[]) => void): void;  // 监听事件
    off(event: string, callback: (...args: any[]) => void): void;  // 取消监听
    toast(msg: string, duration?: 0 | 1): void;  // 显示提示信息
}
```

### 事件系统

组件会发出事件，可以监听这些事件：

```typescript
// 组件级别的事件
component.on('valueChanged', (value) => {
    // Switch、Selector、Slider 等组件的值改变时触发
    console.log('值改变:', value);
});

component.on('click', () => {
    // Button 组件点击时触发
    console.log('按钮被点击');
});

// Menu 会转发组件事件并带上组件 ID
menu.on('component:mySwitch:valueChanged', (value) => {
    console.log('ID 为 "mySwitch" 的组件值改变为:', value);
});
```

## 📂 项目结构

```
frida-float-menu/
├── src/                    # 库源代码
│   ├── index.ts           # 主入口（重新导出所有内容）
│   ├── float-menu.ts      # FloatMenu 主类
│   ├── event-emitter.ts   # 事件系统
│   ├── logger.ts          # 日志工具
│   └── component/         # 组件目录
│       ├── button.ts      # 按钮组件
│       ├── text.ts        # 文本组件
│       ├── switch.ts      # 开关组件
│       ├── selector.ts    # 选择器组件
│       ├── slider.ts      # 滑块组件
│       ├── input.ts       # 输入框组件
│       ├── checkBox.ts    # 多选框组件
│       ├── category.ts    # 分类标题组件
│       ├── collapsible.ts # 可折叠面板组件
│       ├── image.ts       # 图片组件
│       ├── ui-components.ts # UI 组件基类
│       └── style/         # 样式相关
│           ├── theme.ts   # 主题配置
│           └── style.ts   # 样式工具
├── example.js             # 编译后的 JavaScript 示例
├── icon.ts                # 图标 base64 编码
├── package.json           # 包配置文件
├── tsconfig.json          # TypeScript 配置
└── README.md              # 本文件
```

## 🛠️ 编译和开发

### 对于库使用者
无需构建 - 直接使用 TypeScript 源代码与 frida-compile 一起使用。

### 对于库开发者
```bash
npm install                    # 安装依赖
npm run check                 # 类型检查
npm run build         # 编译示例脚本
```

## 📖 使用示例

### 查看完整示例

`example.ts` 包含了所有组件的详细使用示例，展示了：

1. **基础组件页**：Text、Button、Category 等基础组件的使用
2. **表单组件页**：TextInput、NumberInput、Switch、CheckBoxGroup 等表单组件
3. **选择组件页**：Selector、Slider 等选择组件
4. **布局组件页**：Collapsible、ImageView 等布局组件
5. **交互演示页**：组件之间的交互和联动效果（用户评分系统、购物车）

### 编译和运行示例

```bash
# 编译示例
frida-compile example.ts -o example-compiled.js -c

# 注入到目标应用
frida -U -f com.example.app -l example-compiled.js
```

## ⚠️ 限制

- 需要 Android API 26+ 才能使用 `TYPE_APPLICATION_OVERLAY`
- UI 操作自动在主线程中调度
- 使用 Android 原生控件（无自定义样式）
- 仅在 Android 上测试（不支持 iOS）

## 📝 许可证

MIT

## 🤝 贡献

欢迎贡献！请提交问题和拉取请求来增强这个库。

## 🔗 相关链接

- [Frida 官网](https://frida.re/)
- [frida-compile 文档](https://github.com/nowsecure/frida-compile)

## 💡 提示

- 使用多标签页可以更好地组织复杂的 UI
- 组件之间可以通过 `menu.getComponent()` 相互访问
- 使用 `menu.setComponentValue()` 可以动态更新 UI
- 日志功能可以帮助调试，但会影响性能
- 所有示例代码都在 `example.ts` 中，可以参考学习