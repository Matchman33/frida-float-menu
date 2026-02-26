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
Java.perform(() => {
  console.log("Java runtime ready, creating floating menu...");

  // Create menu configuration
  const options: FloatMenuOptions = {
    width: 600,
    height: 500,
    x: 0,
    y: 0,
    showLogs: false,
    logMaxLines: 50,
    
    iconBase64: iconBase64,
  };

  const menu = new FloatMenu(options);
  
  menu.show();
  //   // Add a button with click handler
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
  menu.addComponent("exampleButton", button);

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

//   // Update UI programmatically after 3 seconds
//   setTimeout(() => {
//     console.log("Programmatically updating UI...");
//     menu.setComponentValue("exampleSwitch", true);
//     text.setText("Updated programmatically!");
//     selector.setItems(["Level 1", "Level 2", "Level 3", "Level 4"]);
//   }, 3000);

  // Hide menu after 20 seconds
//   setTimeout(() => {
//     menu.hide();
//     console.log("Menu hidden after timeout");
//   }, 20000);
  menu.show();

  console.log("FloatMenu example initialized. UI should be visible.");
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
