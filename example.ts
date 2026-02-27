// TypeScript example for FloatMenu library
// This shows the recommended way to use the library in TypeScript projects

import { iconBase64 } from "./icon";
import {
  Button,
  FloatMenu,
  FloatMenuOptions,
  Selector,
  Switch,
  Text,
} from "./src/index";

// Optional: attach to global for easier access in Frida REPL
// import { attachToGlobal } from './src/index';
// attachToGlobal(globalThis);

// Set this to true to enable tabs example, false for basic example
const USE_TABS = false;

Java.perform(() => {
  console.log("Java runtime ready, creating floating menu...");

  if (USE_TABS) {
    // === EXAMPLE WITH TABS ===
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
      title: "Frida Float Menu with Tabs",
      subtitle: "Multiple tabbed panels",
      showHeader: true,
      showFooter: true,
      tabs: [
        { id: "tab1", label: "Controls" },
        { id: "tab2", label: "Settings" },
        { id: "tab3", label: "Info" },
      ],
      activeTab: "tab1",
      showTabs: true,
    };

    const menu = new FloatMenu(options);
    menu.show();

    // Listen for tab changes
    menu.on("tabChanged", (newTabId: string, oldTabId: string) => {
      console.log(`Tab changed: ${oldTabId} -> ${newTabId}`);
    });

    // === Add components to Tab 1 (Controls) ===
    const button1 = new Button("tab1_button", "Toggle Switch");
    button1.setOnClick(() => {
      console.log("Button in Tab 1 clicked");
      const switchComp = menu.getComponent<Switch>("tab1_switch");
      if (switchComp) {
        const current = switchComp.getValue();
        switchComp.setValue(!current);
      }
    });
    menu.addComponent("tab1_button", button1, "tab1");

    const switch1 = new Switch("tab1_switch", "Auto-update", false);
    menu.addComponent("tab1_switch", switch1, "tab1");

    const text1 = new Text("tab1_text", "<b>Tab 1: Controls</b><br/>Use buttons and switches here.");
    menu.addComponent("tab1_text", text1, "tab1");

    // === Add components to Tab 2 (Settings) ===
    const selector2 = new Selector("tab2_selector", ["Low", "Medium", "High"], 1);
    selector2.on("valueChanged", (value: string) => {
      console.log(`Selected: ${value}`);
      menu.setComponentValue("tab2_text", `Current level: <b>${value}</b>`);
    });
    menu.addComponent("tab2_selector", selector2, "tab2");

    const text2 = new Text("tab2_text", "Select a difficulty level");
    menu.addComponent("tab2_text", text2, "tab2");

    const switch2 = new Switch("tab2_switch", "Enable Feature", true);
    menu.addComponent("tab2_switch", switch2, "tab2");

    // === Add components to Tab 3 (Info) ===
    const text3 = new Text("tab3_text", "<h3>Tab 3: Information</h3><p>This tab shows static information.</p><p>You can add any UI components to any tab.</p>");
    menu.addComponent("tab3_text", text3, "tab3");

    const button3 = new Button("tab3_button", "Show Alert");
    button3.setOnClick(() => {
      console.log("Alert button clicked!");
      menu.setComponentValue("tab3_text", "<h3>Alert!</h3><p>Button was clicked at " + new Date().toLocaleTimeString() + "</p>");
    });
    menu.addComponent("tab3_button", button3, "tab3");

    console.log("FloatMenu with tabs initialized. Try clicking tabs at the top.");

    // Programmatically switch tabs after 5 seconds
    setTimeout(() => {
      console.log("Switching to Tab 2 programmatically...");
      menu.switchTab("tab2");
    }, 5000);

  } else {
    // === BASIC EXAMPLE WITHOUT TABS (legacy) ===
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
    };
    console.log("Delayed menu creation after Unity init");
    const menu = new FloatMenu(options);

    menu.show();
    // Add a button with click handler
    const button = new Button("exampleButton", "Click Me!");
    button.setOnClick(() => {
      console.log("Button was clicked!");
      // Toggle the switch when button is clicked
      const switchComp = menu.getComponent<Switch>("exampleSwitch");
      if (switchComp) {
        const currentValue = switchComp.getValue();
        switchComp.setValue(!currentValue);
      }
    });
    const button1 = new Button("exampleButton1", "Click Me!111");
    button1.setOnClick(() => {
      console.log("Button1 was clicked!");
      // Toggle the switch when button is clicked
      const switchComp = menu.getComponent<Switch>("exampleSwitch");
      if (switchComp) {
        switchComp.setValue(true);
      }
    });
    menu.addComponent("exampleButton", button);
    menu.addComponent("exampleButton1", button1);

    // Add a switch with value change listener
    const switchComp = new Switch("exampleSwitch", "Auto-update", false);

    menu.addComponent("exampleSwitch", switchComp);

    // Add text display
    const text = new Text("exampleText", "<h1>hello</h1>");
    menu.addComponent("exampleText", text);

    // Add selector with options
    const selector = new Selector(
      "exampleSelector",
      ["Easy", "Medium", "Hard"],
      0,
    );
    selector.on("valueChanged", (value: string) => {
      console.log("Difficulty selected:", value);
      menu.setComponentValue("exampleText", `Difficulty: ${value}`);
    });
    menu.addComponent("exampleSelector", selector);

    // Demonstrate menu-level event listening
    menu.on("component:exampleSwitch:valueChanged", (value: boolean) => {
      console.log("[Menu] Switch changed via menu event:", value);
    });

    console.log("FloatMenu example initialized. UI should be visible.");
  }
});

// Compilation instructions:
// 1. Install dependencies: npm install
// 2. Compile this example: frida-compile example.ts -o example-compiled.js -c
// 3. Inject into target: frida -U -f com.example.app -l example-compiled.js
//
// For your own projects:
// 1. Copy the src/ directory to your project
// 2. Import from the local copy: import { FloatMenu } from './path/to/src/index';
// 3. Compile your script with frida-compile
