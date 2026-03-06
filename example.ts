// 综合测试用例 - 展示所有组件
// 将所有组件按照类型分组在不同的标签页中

import { iconBase64 } from "./icon";
import {
  Button,
  FloatMenu,
  FloatMenuOptions,
  Text,
  Category,
  Switch,
  Collapsible,
} from "./src/index";
import { NumberInput, TextInput } from "./src/component/input";
import { CheckBoxGroup } from "./src/component/checkBox";
import { ImageView } from "./src/component/image";
import { DarkNeonTheme } from "./src/component/style/theme";
import { Selector } from "./src/component/selector";
import { Slider } from "./src/component/slider";

Java.perform(() => {

  const options: FloatMenuOptions = {
    width: 1200,
    height: 1400,
    x: 0,
    y: 0,
    theme: DarkNeonTheme,
    iconWidth: 200,
    iconHeight: 200,
    logMaxLines: 50,
    iconBase64: iconBase64,
    title: "综合测试用例",
    tabs: [
      { id: "basic", label: "基础组件" },
      { id: "form", label: "表单组件" },
      { id: "selection", label: "选择组件" },
      { id: "layout", label: "布局组件" },
      { id: "interactive", label: "交互演示" },
    ],
  };

  const menu = new FloatMenu(options);
  menu.show();
  menu.logger.info("开始创建综合测试用例，涵盖所有组件...");

  menu.logger.info("悬浮窗已创建，开始添加组件...");

  // ============================================
  // 标签页1: 基础组件 (Basic Components)
  // ============================================
  
  const basicCategory = new Category("basic_category", "基础组件");
  menu.addComponent(basicCategory, "basic");

  // Text 组件
  const textComponent = new Text(
    "basic_text",
    "这是一个文本组件，用于显示静态或动态的文本内容。"
  );
  menu.addComponent(textComponent, "basic");

  // Text 组件（带HTML富文本）
  const richText = new Text(
    "rich_text",
    "HTML <b>富文本</b> 支持：<br/>- <b>粗体</b><br/>- <i>斜体</i><br/>- <u>下划线</u>"
  );
  menu.addComponent(richText, "basic");

  // Text 组件（动态更新）
  const dynamicText = new Text("dynamic_text", "动态文本：点击按钮更新");
  menu.addComponent(dynamicText, "basic");

  // Primary Button
  const primaryButton = new Button("primary_button", "主要按钮", "primary");
  primaryButton.setOnClick(() => {
    menu.logger.info("主要按钮被点击");
    menu.toast("主要按钮被点击！");
    // 动态更新文本
    menu.setComponentValue("dynamic_text", `动态文本：最后更新于 ${new Date().toLocaleTimeString()}`);
  });
  menu.addComponent(primaryButton, "basic");

  // Danger Button
  const dangerButton = new Button("danger_button", "危险操作", "danger");
  dangerButton.setOnClick(() => {
    menu.logger.info("危险按钮被点击");
    menu.toast("这是一个危险操作！", 1);
  });
  menu.addComponent(dangerButton, "basic");

  // Category 组件
  const section1 = new Category("section1", "分类标题1");
  menu.addComponent(section1, "basic");

  // ============================================
  // 标签页2: 表单组件 (Form Components)
  // ============================================
  
  const formCategory = new Category("form_category", "表单组件");
  menu.addComponent(formCategory, "form");

  // TextInput - 用户名输入
  const usernameInput = new TextInput(
    "username",
    "",
    "用户名",
    "请输入用户名",
    "输入用户名"
  );
  usernameInput.setOnValueChange((value: string) => {
    menu.logger.info(`用户名输入: ${value}`);
    menu.toast(`用户名设置为: ${value}`);
    // 更新显示文本
    menu.setComponentValue("username_display", `当前用户名：<b>${value || "未设置"}</b>`);
  });
  menu.addComponent(usernameInput, "form");

  // 显示用户名的文本
  const usernameDisplay = new Text("username_display", "当前用户名：<b>未设置</b>");
  menu.addComponent(usernameDisplay, "form");

  // TextInput - 密码输入
  const passwordInput = new TextInput(
    "password",
    "",
    "密码",
    "请输入密码",
    "输入密码"
  );
  passwordInput.setOnValueChange((value: string) => {
    menu.logger.info(`密码输入: ${value.length} 个字符`);
  });
  menu.addComponent(passwordInput, "form");

  // TextInput - 备注输入（多行）
  const notesInput = new TextInput(
    "notes",
    "",
    "备注",
    "请输入备注信息...",
    "输入备注"
  );
  notesInput.setOnValueChange((value: string) => {
    const chars = value.length;
    const lines = value.split("\n").length;
    menu.setComponentValue(
      "notes_stats",
      `备注统计：<br/>- 字符数: ${chars}<br/>- 行数: ${lines}`
    );
  });
  menu.addComponent(notesInput, "form");

  // 备注统计文本
  const notesStats = new Text("notes_stats", "备注统计：<br/>- 字符数: 0<br/>- 行数: 0");
  menu.addComponent(notesStats, "form");

  // NumberInput - 年龄
  const ageInput = new NumberInput(
    "age",
    25,
    0,  // 最小值
    120, // 最大值
    "年龄：",
    "请输入年龄",
    "输入年龄"
  );
  ageInput.setOnValueChange((value: number) => {
    menu.logger.info(`年龄设置为: ${value}`);
    let category = "";
    if (value < 13) category = "儿童";
    else if (value < 20) category = "青少年";
    else if (value < 65) category = "成年人";
    else category = "老年人";
    menu.setComponentValue("age_display", `年龄段：<b>${category}</b>`);
  });
  menu.addComponent(ageInput, "form");

  // 年龄段显示
  const ageDisplay = new Text("age_display", "年龄段：<b>成年人</b>");
  menu.addComponent(ageDisplay, "form");

  // NumberInput - 数量（带步进）
  const quantityInput = new NumberInput(
    "quantity",
    10,
    0,
    100,
    "数量：",
    "请输入数量",
    "输入数量"
  );
  quantityInput.setOnValueChange((value: number) => {
    const price = 99.99;
    const total = (value * price).toFixed(2);
    menu.setComponentValue(
      "total_price",
      `单价: ¥${price}<br/>总计: ¥${total}`
    );
  });
  menu.addComponent(quantityInput, "form");

  // 价格总计显示
  const totalPrice = new Text("total_price", "单价: ¥99.99<br/>总计: ¥999.90");
  menu.addComponent(totalPrice, "form");

  // Switch - 音效开关
  const soundSwitch = new Switch("sound_switch", "音效");
  soundSwitch.on("valueChanged", (value: boolean) => {
    menu.logger.info(`音效开关: ${value}`);
    menu.toast(`音效已${value ? "开启" : "关闭"}`);
  });
  menu.addComponent(soundSwitch, "form");

  // Switch - 通知开关
  const notificationSwitch = new Switch("notification_switch", "通知");
  notificationSwitch.on("valueChanged", (value: boolean) => {
    menu.logger.info(`通知开关: ${value}`);
    menu.toast(`通知已${value ? "开启" : "关闭"}`);
  });
  menu.addComponent(notificationSwitch, "form");

  // CheckBoxGroup - 爱好选择（多选）
  const hobbiesGroup = new CheckBoxGroup(
    "hobbies",
    [
      { id: "reading", label: "阅读" },
      { id: "music", label: "音乐" },
      { id: "sports", label: "运动" },
      { id: "travel", label: "旅行" },
      { id: "gaming", label: "游戏" },
    ],
    ["reading"] // 初始选中阅读
  );
  hobbiesGroup.on("valueChanged", (values: any[]) => {
    menu.logger.info(`选中的爱好: ${JSON.stringify(values)}`);
    // menu.toast(`选中的爱好: ${values.join(", ")}`);
    menu.setComponentValue("hobbies_display", `选中的爱好：<b>${values.map((v) => v.label).join(", ") || "无"}</b>`);
  });
  menu.addComponent(hobbiesGroup, "form");

  // 爱好显示文本
  const hobbiesDisplay = new Text("hobbies_display", "选中的爱好：<b>阅读</b>");
  menu.addComponent(hobbiesDisplay, "form");

  // ============================================
  // 标签页3: 选择组件 (Selection Components)
  // ============================================
  
  const selectionCategory = new Category("selection_category", "选择组件");
  menu.addComponent(selectionCategory, "selection");

  // Selector - 城市选择
  const citySelector = new Selector(
    "city_selector",
    [
      { lable: "北京", code: "BJ" },
      { lable: "上海", code: "SH" },
      { lable: "广州", code: "GZ" },
      { lable: "深圳", code: "SZ" },
      { lable: "杭州", code: "HZ" },
      { lable: "成都", code: "CD" },
    ],
    0 // 默认选中第一个
  );
  citySelector.on("valueChanged", (value: any) => {
    menu.logger.info(`选择的城市: ${value.lable} (${value.code})`);
    menu.setComponentValue("city_display", `当前城市：<b>${value.lable}</b>`);
  });
  menu.addComponent(citySelector, "selection");

  // 城市显示文本
  const cityDisplay = new Text("city_display", "当前城市：<b>北京</b>");
  menu.addComponent(cityDisplay, "selection");

  // Selector - 颜色选择
  const colorSelector = new Selector(
    "color_selector",
    [
      { lable: "红色", color: "#FF0000" },
      { lable: "绿色", color: "#00FF00" },
      { lable: "蓝色", color: "#0000FF" },
      { lable: "黄色", color: "#FFFF00" },
      { lable: "紫色", color: "#FF00FF" },
    ],
    0
  );
  colorSelector.on("valueChanged", (value: any) => {
    menu.logger.info(`选择的颜色: ${value.lable} (${value.color})`);
    menu.toast(`颜色设置为: ${value.lable}`);
  });
  menu.addComponent(colorSelector, "selection");

  // Selector - 语言选择
  const languageSelector = new Selector(
    "language_selector",
    [
      { lable: "简体中文", lang: "zh-CN" },
      { lable: "繁體中文", lang: "zh-TW" },
      { lable: "English", lang: "en-US" },
      { lable: "日本語", lang: "ja-JP" },
      { lable: "한국어", lang: "ko-KR" },
    ],
    0
  );
  languageSelector.on("valueChanged", (value: any) => {
    menu.logger.info(`选择的语言: ${value.lable}`);
    menu.toast(`语言设置为: ${value.lable}`);
  });
  menu.addComponent(languageSelector, "selection");

  // Slider - 音量控制
  const volumeSlider = new Slider(
    "volume_slider",
    "音量控制",
    0,   // 最小值
    100, // 最大值
    50,  // 初始值
    1    // 步进
  );
  volumeSlider.on("valueChanged", (value: number) => {
    menu.logger.info(`音量: ${value}%`);
    menu.setComponentValue("volume_display", `当前音量：<b>${value}%</b>`);
  });
  menu.addComponent(volumeSlider, "selection");

  // 音量显示文本
  const volumeDisplay = new Text("volume_display", "当前音量：<b>50%</b>");
  menu.addComponent(volumeDisplay, "selection");

  // Slider - 亮度控制
  const brightnessSlider = new Slider(
    "brightness_slider",
    "亮度控制",
    0,
    100,
    75,
    5
  );
  brightnessSlider.on("valueChanged", (value: number) => {
    menu.logger.info(`亮度: ${value}%`);
    menu.setComponentValue("brightness_display", `当前亮度：<b>${value}%</b>`);
  });
  menu.addComponent(brightnessSlider, "selection");

  // 亮度显示文本
  const brightnessDisplay = new Text("brightness_display", "当前亮度：<b>75%</b>");
  menu.addComponent(brightnessDisplay, "selection");

  // Slider - 进度控制
  const progressSlider = new Slider(
    "progress_slider",
    "进度控制",
    0,
    1000,
    0,
    10
  );
  progressSlider.on("valueChanged", (value: number) => {
    menu.logger.info(`进度: ${value}`);
    const percentage = ((value / 1000) * 100).toFixed(1);
    menu.setComponentValue(
      "progress_display",
      `当前进度：<b>${value}</b> / 1000 (${percentage}%)`
    );
  });
  menu.addComponent(progressSlider, "selection");

  // 进度显示文本
  const progressDisplay = new Text("progress_display", "当前进度：<b>0</b> / 1000 (0.0%)");
  menu.addComponent(progressDisplay, "selection");

  // ============================================
  // 标签页4: 布局组件 (Layout Components)
  // ============================================
  
  const layoutCategory = new Category("layout_category", "布局组件");
  menu.addComponent(layoutCategory, "layout");

  // Collapsible - 用户设置（展开状态）
  const userSettingsCollapsible = new Collapsible("user_settings", "用户设置", true);
  
  // 在 Collapsible 中添加组件
  const usernameInput2 = new TextInput(
    "username2",
    "admin",
    "用户名",
    "请输入用户名",
    "修改用户名"
  );
  usernameInput2.setOnValueChange((value: string) => {
    menu.logger.info(`用户名修改: ${value}`);
    menu.toast(`用户名已修改为: ${value}`);
  });

  const emailInput = new TextInput(
    "email",
    "admin@example.com",
    "邮箱",
    "请输入邮箱地址",
    "修改邮箱"
  );
  emailInput.setOnValueChange((value: string) => {
    menu.logger.info(`邮箱修改: ${value}`);
    menu.toast(`邮箱已修改为: ${value}`);
  });

  const roleSelector = new Selector(
    "role_selector",
    [
      { lable: "管理员", role: "admin" },
      { lable: "普通用户", role: "user" },
      { lable: "访客", role: "guest" },
    ],
    0
  );

  userSettingsCollapsible.addChildren([
    usernameInput2,
    emailInput,
    roleSelector
  ]);
  
  menu.addComponent(userSettingsCollapsible, "layout");

  // Collapsible - 系统配置（折叠状态）
  const systemConfigCollapsible = new Collapsible("system_config", "系统配置", false);
  
  const logLevelSelector = new Selector(
    "log_level",
    [
      { lable: "调试 (DEBUG)", level: 0 },
      { lable: "信息 (INFO)", level: 1 },
      { lable: "警告 (WARN)", level: 2 },
      { lable: "错误 (ERROR)", level: 3 },
    ],
    1
  );
  
  const cacheSizeInput = new NumberInput(
    "cache_size",
    100,
    10,
    1000,
    "缓存大小",
    "请输入缓存大小(MB)",
    "设置缓存大小"
  );
  
  const autoUpdateSwitch = new Switch("auto_update", "自动更新");

  systemConfigCollapsible.addChildren([
    logLevelSelector,
    cacheSizeInput,
    autoUpdateSwitch
  ]);
  
  menu.addComponent(systemConfigCollapsible, "layout");

  // ImageView - 显示图标
  const imageView = new ImageView(
    "logo_image",
    iconBase64,
    400, // 宽度
    400  // 高度
  );
  menu.addComponent(imageView, "layout");

  // ============================================
  // 标签页5: 交互演示 (Interactive Demo)
  // ============================================
  
  const interactiveCategory = new Category("interactive_category", "交互演示");
  menu.addComponent(interactiveCategory, "interactive");

  // 演示说明
  const demoDescription = new Text(
    "demo_description",
    "此页面演示组件之间的交互和联动效果"
  );
  menu.addComponent(demoDescription, "interactive");

  // 复合组件：用户评分系统
  const ratingCollapsible = new Collapsible("rating_system", "用户评分系统", true);
  
  // 用户名
  const raterInput = new TextInput(
    "rater_name",
    "",
    "评分人",
    "请输入姓名",
    "输入姓名"
  );
  
  // 评分滑块
  const ratingSlider = new Slider(
    "rating_slider",
    "评分 (1-10)",
    1,
    10,
    8,
    1
  );
  ratingSlider.on("valueChanged", (value: number) => {
    let ratingText = "";
    if (value <= 3) ratingText = "不满意";
    else if (value <= 6) ratingText = "一般";
    else if (value <= 8) ratingText = "满意";
    else ratingText = "非常满意";
    menu.setComponentValue("rating_display", `${ratingText}`);
  });
  
  // 评分显示
  const ratingDisplay = new Text("rating_display", "满意");
  
  // 评分标签
  const tagsGroup = new CheckBoxGroup(
    "rating_tags",
    [
      { id: "fast", label: "响应快" },
      { id: "stable", label: "稳定" },
      { id: "easy_use", label: "易用" },
      { id: "beautiful", label: "美观" },
    ],
    []
  );
  
  // 评论文本
  const commentInput = new TextInput(
    "rating_comment",
    "",
    "评论",
    "请输入您的评论...",
    "添加评论"
  );
  
  // 提交按钮
  const submitRatingButton = new Button("submit_rating", "提交评分", "primary");
  submitRatingButton.setOnClick(() => {
    const rater = menu.getComponent<TextInput>("rater_name")?.getValue() || "";
    const rating = menu.getComponent<Slider>("rating_slider")?.getValue();
    const tags = menu.getComponent<CheckBoxGroup>("rating_tags")?.getCheckedValues() || [];
    const comment = menu.getComponent<TextInput>("rating_comment")?.getValue() || "";
    
    menu.logger.info("提交评分:", {
      rater,
      rating,
      tags,
      comment
    });
    
    menu.toast(
      `评分已提交！\n评分人: ${rater}\n得分: ${rating}\n标签: ${tags.join(", ")}\n评论: ${comment}`,
      1
    );
  });

  const ratingDisplayText = new Text(
    "rating_result",
    "点击提交按钮查看结果"
  );

  ratingCollapsible.addChildren([
    raterInput,
    ratingSlider,
    ratingDisplay,
    tagsGroup,
    commentInput,
    submitRatingButton,
    ratingDisplayText
  ]);
  
  menu.addComponent(ratingCollapsible, "interactive");

  // 复合组件：购物车
  const cartCollapsible = new Collapsible("shopping_cart", "购物车", false);
  
  // 商品选择器
  const productSelector = new Selector(
    "product_selector",
    [
      { lable: "笔记本电脑", price: 5999 },
      { lable: "鼠标", price: 99 },
      { lable: "键盘", price: 299 },
      { lable: "显示器", price: 1999 },
      { lable: "耳机", price: 399 },
    ],
    0
  );
  productSelector.on("valueChanged", (value: any) => {
    const quantity = menu.getComponent<NumberInput>("cart_quantity")?.getValue() || 1;
    const total = (value.price * quantity).toFixed(2);
    menu.setComponentValue("cart_total", `总价: ¥${total}`);
  });
  
  // 数量输入
  const quantitySelector = new NumberInput(
    "cart_quantity",
    1,
    1,
    10,
    "数量",
    "请输入数量",
    "修改数量"
  );
  quantitySelector.setOnValueChange((value: number) => {
    const product = menu.getComponent<Selector>("product_selector")?.getValue();
    if (product) {
      const total = (product.price * value).toFixed(2);
      menu.setComponentValue("cart_total", `总价: ¥${total}`);
    }
  });
  
  // 运费选择器
  const shippingSelector = new Selector(
    "shipping_selector",
    [
      { lable: "普通快递 (¥10)", fee: 10 },
      { lable: "加急快递 (¥20)", fee: 20 },
      { lable: "顺丰速运 (¥25)", fee: 25 },
    ],
    0
  );
  shippingSelector.on("valueChanged", (value: any) => {
    const product = menu.getComponent<Selector>("product_selector")?.getValue();
    const quantity = menu.getComponent<NumberInput>("cart_quantity")?.getValue() || 1;
    const subtotal = product ? product.price * quantity : 0;
    const total = (subtotal + value.fee).toFixed(2);
    menu.setComponentValue(
      "cart_total",
      `商品总价: ¥${subtotal.toFixed(2)}<br/>运费: ¥${value.fee}<br/>总计: ¥${total}`
    );
  });
  
  // 总价显示
  const cartTotal = new Text("cart_total", "总价: ¥5999");
  menu.addComponent(cartTotal, "interactive");
  
  // 添加到购物车
  cartCollapsible.addChildren([
    productSelector,
    quantitySelector,
    shippingSelector
  ]);
  
  menu.addComponent(cartCollapsible, "interactive");

  // 添加到购物车按钮
  const addToCartButton = new Button("add_to_cart", "添加到购物车", "primary");
  addToCartButton.setOnClick(() => {
    const product = menu.getComponent<Selector>("product_selector")?.getValue();
    const quantity = menu.getComponent<NumberInput>("cart_quantity")?.getValue() || 1;
    const shipping = menu.getComponent<Selector>("shipping_selector")?.getValue();
    
    if (!product || !shipping) {
      menu.toast("请先选择商品和配送方式", 1);
      return;
    }
    
    const subtotal = product.price * quantity;
    const total = subtotal + shipping.fee;
    
    menu.toast(
      `已添加到购物车！\n商品: ${product.lable}\n数量: ${quantity}\n配送: ${shipping.lable}\n总计: ¥${total.toFixed(2)}`,
      1
    );
  });
  menu.addComponent(addToCartButton, "interactive");

  // ============================================
  // 全局事件监听示例
  // ============================================
  
  menu.on("component:username:valueChanged", (value: string) => {
    menu.logger.info(`[全局监听] 用户名改变: ${value}`);
  });

  menu.on("component:volume_slider:valueChanged", (value: number) => {
    menu.logger.info(`[全局监听] 音量改变: ${value}%`);
  });

  menu.on("component:sound_switch:valueChanged", (value: boolean) => {
    menu.logger.info(`[全局监听] 音效开关: ${value}`);
  });

  menu.logger.info("所有组件已添加完成！");
  menu.toast("综合测试用例已加载完成");
});

// 编译说明：
// 1. 安装依赖: npm install
// 2. 编译此文件: frida-compile test-all-components.ts -o test-all-components.js -c
// 3. 注入到目标应用: frida -U -f com.example.app -l test-all-components.js
//
// 说明：
// - 基础组件页：展示 Text、Button、Category 等基础组件
// - 表单组件页：展示 TextInput、NumberInput、Switch、CheckBoxGroup 等表单组件
// - 选择组件页：展示 Selector、Slider 等选择组件
// - 布局组件页：展示 Collapsible、ImageView 等布局组件
// - 交互演示页：展示组件之间的交互和联动效果