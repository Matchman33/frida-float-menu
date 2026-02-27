// Demo for new FloatMenu UI components
// Demonstrates Slider, Collapsible, Category, TextInput, and NumberInput components

import { iconBase64 } from "./icon";
import {
  Button,
  FloatMenu,
  FloatMenuOptions,
  Switch,
  Text,
  Selector,
  Slider,
  Collapsible,
  Category,
  TextInput,
  NumberInput,
} from "./src/index";

// Optional: attach to global for easier access in Frida REPL
// import { attachToGlobal } from './src/index';
// attachToGlobal(globalThis);

Java.perform(() => {
  console.log("Java runtime ready, creating floating menu with new components...");

  const options: FloatMenuOptions = {
    width: 1000,
    height: 900,
    x: -100,
    y: 0,
    iconWidth: 200,
    iconHeight: 200,
    showLogs: false,
    logMaxLines: 50,
    iconBase64: iconBase64,
    title: "Frida Float Menu - New Components Demo",
    subtitle: "Slider, Collapsible, Category, TextInput, NumberInput",
    showHeader: true,
    showFooter: true,
    tabs: [
      { id: "controls", label: "Controls" },
      { id: "inputs", label: "Inputs" },
      { id: "layout", label: "Layout" },
    ],
    activeTab: "controls",
    showTabs: true,
  };

  const menu = new FloatMenu(options);
  menu.show();

  // Listen for tab changes
  menu.on("tabChanged", (newTabId: string, oldTabId: string) => {
    console.log(`Tab changed: ${oldTabId} -> ${newTabId}`);
  });

  // === Tab 1: Controls (Slider, Switch, Button) ===

  // Category separator
  const catControls = new Category("controls_cat", "Control Components");
  menu.addComponent("controls_cat", catControls, "controls");

  // Slider component
  const slider = new Slider("volume_slider", "Volume", 0, 100, 50, 5);
  slider.on("valueChanged", (value: number) => {
    console.log(`Slider value changed: ${value}`);
    menu.setComponentValue("slider_value_text", `Current volume: <b>${value}%</b>`);

    // Update another component based on slider value
    if (value > 80) {
      menu.setComponentValue("warning_text", "<font color='red'>⚠ Warning: Volume too high!</font>");
    } else {
      menu.setComponentValue("warning_text", "");
    }
  });
  menu.addComponent("volume_slider", slider, "controls");

  // Text to display slider value
  const sliderValueText = new Text("slider_value_text", "Current volume: <b>50%</b>");
  menu.addComponent("slider_value_text", sliderValueText, "controls");

  // Warning text (updated by slider)
  const warningText = new Text("warning_text", "");
  menu.addComponent("warning_text", warningText, "controls");

  // Button to reset slider
  const resetButton = new Button("reset_button", "Reset Slider");
  resetButton.setOnClick(() => {
    console.log("Reset button clicked");
    slider.setValue(50);
    menu.setComponentValue("slider_value_text", "Current volume: <b>50%</b>");
    menu.setComponentValue("warning_text", "");
  });
  menu.addComponent("reset_button", resetButton, "controls");

  // Button to change slider range
  const rangeButton = new Button("range_button", "Change Range (0-200)");
  rangeButton.setOnClick(() => {
    console.log("Range button clicked");
    slider.setRange(0, 200, 10);
    menu.setComponentValue("slider_value_text", "Slider range changed to 0-200, step 10");
  });
  menu.addComponent("range_button", rangeButton, "controls");

  // Switch example
  const autoSwitch = new Switch("auto_switch", "Auto-adjust", false);
  autoSwitch.on("valueChanged", (value: boolean) => {
    console.log(`Auto-adjust switch: ${value}`);
    menu.setComponentValue("switch_status", `Auto-adjust: <b>${value ? "ON" : "OFF"}</b>`);

    // Enable/disable slider based on switch
    if (value) {
      menu.setComponentValue("slider_info", "<i>Slider is now controlled automatically</i>");
    } else {
      menu.setComponentValue("slider_info", "<i>Slider is now manual control</i>");
    }
  });
  menu.addComponent("auto_switch", autoSwitch, "controls");

  const switchStatus = new Text("switch_status", "Auto-adjust: <b>OFF</b>");
  menu.addComponent("switch_status", switchStatus, "controls");

  const sliderInfo = new Text("slider_info", "<i>Slider is now manual control</i>");
  menu.addComponent("slider_info", sliderInfo, "controls");

  // === Tab 2: Inputs (TextInput, NumberInput) ===

  // Category separator
  const catInputs = new Category("inputs_cat", "Input Components");
  menu.addComponent("inputs_cat", catInputs, "inputs");

  // TextInput component (single line)
  const textInput = new TextInput("name_input", "John Doe", "Enter your name");
  textInput.on("valueChanged", (value: string) => {
    console.log(`TextInput changed: "${value}"`);
    menu.setComponentValue("name_display", `Hello, <b>${value || "Anonymous"}</b>!`);
  });
  menu.addComponent("name_input", textInput, "inputs");
  

  const nameDisplay = new Text("name_display", "Hello, <b>John Doe</b>!");
  menu.addComponent("name_display", nameDisplay, "inputs");

  const JString = Java.use("java.lang.String")
  // Button to clear text input
  const clearTextButton = new Button("clear_text_button", "Clear Name");
  clearTextButton.setOnClick(() => {
    console.log("Clear name button clicked");
    textInput.setText(JString.$new(""));
    menu.setComponentValue("name_display", "Hello, <b>Anonymous</b>!");
  });
  menu.addComponent("clear_text_button", clearTextButton, "inputs");

  // TextInput component (multiline)
  const multiInput = new TextInput("notes_input", "", "Enter notes here...", true);
  multiInput.on("valueChanged", (value: string) => {
    console.log(`Notes changed (${value.length} characters)`);

    // Count lines and characters
    const lines = value.split('\n').length;
    const chars = value.length;
    menu.setComponentValue("notes_stats", `Lines: ${lines}, Characters: ${chars}`);
  });
  menu.addComponent("notes_input", multiInput, "inputs");

  const notesStats = new Text("notes_stats", "Lines: 1, Characters: 0");
  menu.addComponent("notes_stats", notesStats, "inputs");

  // NumberInput component
  const numberInput = new NumberInput(
    "age_input",
    25,
    "Enter your age",
    0,  // min
    120, // max
    1   // step
  );
  numberInput.on("valueChanged", (value: number) => {
    console.log(`Age changed: ${value}`);

    // Categorize age
    let category = "";
    if (value < 13) category = "Child";
    else if (value < 20) category = "Teenager";
    else if (value < 65) category = "Adult";
    else category = "Senior";

    menu.setComponentValue("age_category", `Age category: <b>${category}</b>`);
  });
  menu.addComponent("age_input", numberInput, "inputs");

  const ageCategory = new Text("age_category", "Age category: <b>Adult</b>");
  menu.addComponent("age_category", ageCategory, "inputs");

  // Button to validate number input
  const validateButton = new Button("validate_button", "Validate Age");
  validateButton.setOnClick(() => {
    const age = numberInput.getNumber();
    if (age < 18) {
      menu.setComponentValue("validation_result", `<font color='orange'>⚠ Under 18 - restricted access</font>`);
    } else if (age >= 100) {
      menu.setComponentValue("validation_result", `<font color='green'>🎉 Congratulations on reaching ${age}!</font>`);
    } else {
      menu.setComponentValue("validation_result", `<font color='green'>✓ Age ${age} is valid</font>`);
    }
  });
  menu.addComponent("validate_button", validateButton, "inputs");

  const validationResult = new Text("validation_result", "");
  menu.addComponent("validation_result", validationResult, "inputs");

  // === Tab 3: Layout (Collapsible, Category, Selector) ===

  // Category separator
  const catLayout = new Category("layout_cat", "Layout Components");
  menu.addComponent("layout_cat", catLayout, "layout");

  // Collapsible component with child components
  const collapsible = new Collapsible("settings_collapsible", "⚙ Advanced Settings", false);
  collapsible.on("toggle", (expanded: boolean) => {
    console.log(`Collapsible ${expanded ? "expanded" : "collapsed"}`);
    menu.setComponentValue("collapsible_status", `Settings panel: <b>${expanded ? "OPEN" : "CLOSED"}</b>`);
  });
  menu.addComponent("settings_collapsible", collapsible, "layout");

  const collapsibleStatus = new Text("collapsible_status", "Settings panel: <b>CLOSED</b>");
  menu.addComponent("collapsible_status", collapsibleStatus, "layout");

  // Add child components to collapsible (these will be inside the collapsible content area)
  const childSwitch = new Switch("advanced_switch", "Expert Mode", false);
  childSwitch.on("valueChanged", (value: boolean) => {
    console.log(`Expert mode: ${value}`);
  });

  const childText = new Text("advanced_text", "<small>Enable expert mode for advanced features</small>");

  // Initialize child components and add to collapsible
  Java.scheduleOnMainThread(() => {
    const context = menu["context"];
    childSwitch.init(context);
    childText.init(context);

    collapsible.addChildView(childSwitch.getView());
    collapsible.addChildView(childText.getView());
  });

  // Button to toggle collapsible
  const toggleButton = new Button("toggle_button", "Toggle Settings Panel");
  toggleButton.setOnClick(() => {
    console.log("Toggle button clicked");
    collapsible.toggle();
  });
  menu.addComponent("toggle_button", toggleButton, "layout");

  // Another collapsible example
  const helpCollapsible = new Collapsible("help_collapsible", "❓ Help & Information", true);
  menu.addComponent("help_collapsible", helpCollapsible, "layout");

  // Add help text to collapsible
  const helpText = new Text("help_text", `
    <h3>New Components Guide</h3>
    <p><b>Slider:</b> Drag to adjust values with min/max/step constraints.</p>
    <p><b>Collapsible:</b> Click title to expand/collapse content area.</p>
    <p><b>Category:</b> Section headers for organizing components.</p>
    <p><b>TextInput:</b> Single or multi-line text entry.</p>
    <p><b>NumberInput:</b> Numeric input with validation.</p>
  `);

  Java.scheduleOnMainThread(() => {
    const context = menu["context"];
    helpText.init(context);
    helpCollapsible.addChildView(helpText.getView());
  });

  // Selector to change theme (demonstrating interaction between components)
  const themeSelector = new Selector(
    "theme_selector",
    ["Light Theme", "Dark Theme", "Blue Theme", "Green Theme"],
    0
  );
  themeSelector.on("valueChanged", (value: string) => {
    console.log(`Theme selected: ${value}`);
    menu.setComponentValue("theme_display", `Current theme: <b>${value}</b>`);

    // Simulate theme change by updating other components
    if (value === "Dark Theme") {
      menu.setComponentValue("theme_effect", "🌙 Dark mode activated");
    } else if (value === "Blue Theme") {
      menu.setComponentValue("theme_effect", "🔵 Blue theme applied");
    } else if (value === "Green Theme") {
      menu.setComponentValue("theme_effect", "🟢 Green theme applied");
    } else {
      menu.setComponentValue("theme_effect", "☀️ Light theme active");
    }
  });
  menu.addComponent("theme_selector", themeSelector, "layout");

  const themeDisplay = new Text("theme_display", "Current theme: <b>Light Theme</b>");
  menu.addComponent("theme_display", themeDisplay, "layout");

  const themeEffect = new Text("theme_effect", "☀️ Light theme active");
  menu.addComponent("theme_effect", themeEffect, "layout");

  // === Global event listeners ===

  // Listen for all component value changes
  menu.on("component:volume_slider:valueChanged", (value: number) => {
    console.log(`[Global] Volume slider changed to ${value}`);
  });

  menu.on("component:name_input:valueChanged", (value: string) => {
    console.log(`[Global] Name input changed to "${value}"`);
  });

  menu.on("component:age_input:valueChanged", (value: number) => {
    console.log(`[Global] Age input changed to ${value}`);
  });

  console.log(`
  ============================================
  FloatMenu New Components Demo Initialized!

  Features demonstrated:
  1. Slider with range, step, and value display
  2. Collapsible panels with expand/collapse
  3. Category headers for organization
  4. TextInput (single and multi-line)
  5. NumberInput with min/max/step constraints

  Try interacting with the components in each tab:
  - Controls: Adjust slider, toggle switches
  - Inputs: Enter text and numbers
  - Layout: Expand/collapse panels, select themes
  ============================================
  `);

  // Programmatically switch tabs to show all features
  // setTimeout(() => {
  //   console.log("Auto-switching to Inputs tab...");
  //   menu.switchTab("inputs");
  // }, 3000);

  // setTimeout(() => {
  //   console.log("Auto-switching to Layout tab...");
  //   menu.switchTab("layout");
  // }, 6000);

  // setTimeout(() => {
  //   console.log("Auto-switching back to Controls tab...");
  //   menu.switchTab("controls");
  // }, 9000);
});

// Compilation instructions:
// 1. Install dependencies: npm install
// 2. Compile this demo: frida-compile demo-new-components.ts -o demo-new-components-compiled.js -c
// 3. Inject into target: frida -U -f com.example.app -l demo-new-components-compiled.js
//
// Note: This demo requires the updated ui-components.ts with all new components
// (Slider, Collapsible, Category, TextInput, NumberInput)