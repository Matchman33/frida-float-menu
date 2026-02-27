// Demo for new FloatMenu UI components
// Demonstrates Slider, Collapsible, Category, TextInput, and NumberInput components

import { iconBase64 } from "./icon";
import {
  Button,
  FloatMenu,
  FloatMenuOptions,
  Text,
  Category,
} from "./src/index";
import { NumberInput, TextInput } from "./src/component/input";

// Optional: attach to global for easier access in Frida REPL
// import { attachToGlobal } from './src/index';
// attachToGlobal(globalThis);

Java.perform(() => {
  console.log(
    "Java runtime ready, creating floating menu with new components...",
  );

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
    subtitle: "这是我美好的一天",
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

  // === Tab 2: Inputs (TextInput, NumberInput) ===

  // Category separator
  const catInputs = new Category("inputs_cat", "Input Components");
  menu.addComponent("inputs_cat", catInputs, "inputs");

  // TextInput component (single line)
  // const textInput = new TextInput("name_input", "John Doe", "Enter your name");
  const textInput = new TextInput("name_input", "John Doe", "Enter your name");
  textInput.on("valueChanged", (value: string) => {
    console.log(`TextInput changed: "${value}"`);
    menu.setComponentValue(
      "name_display",
      `Hello, <b>${value || "Anonymous"}</b>!`,
    );
  });
  menu.addComponent("name_input", textInput, "inputs");

  const nameDisplay = new Text("name_display", "Hello, <b>John Doe</b>!");
  menu.addComponent("name_display", nameDisplay, "inputs");

  // Button to clear text input
  const clearTextButton = new Button("clear_text_button", "Clear Name");
  clearTextButton.setOnClick(() => {
    console.log("Clear name button clicked");
    textInput.setText("123");
    menu.setComponentValue("name_display", "Hello, <b>Anonymous</b>!");
  });
  menu.addComponent("clear_text_button", clearTextButton, "inputs");

  // TextInput component (multiline)
  const multiInput = new TextInput(
    "notes_input",
    "",
    "Enter notes here...",
    "notes here",
  );
  multiInput.setOnValueChange((value: string) => {
    console.log(`Notes changed (${value.length} characters)`);

    // Count lines and characters
    const lines = value.split("\n").length;
    const chars = value.length;
    menu.setComponentValue(
      "notes_stats",
      `Lines: ${lines}, Characters: ${chars}`,
    );
  });
  menu.addComponent("notes_input", multiInput, "inputs");

  // NumberInput component
  const numberInput = new NumberInput(
    "age_input",
    25,
    0, // min
    120, // max
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

  Features demonstrated:s
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
