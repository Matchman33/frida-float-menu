// Re-export all public API from the library

// Event system
export { EventEmitter } from "./event-emitter";

// Logging system
export { Logger, LogLevel, log } from "./logger";

// UI Components
export {
  UIComponent,
  Button,
  Switch,
  Text,
  Selector,
  Slider,
  Collapsible,
  Category,
} from "./ui-components";

// FloatMenu main class
export { FloatMenu, FloatMenuOptions, TabDefinition } from "./float-menu";

// Import the classes for use in attachToGlobal function
import { FloatMenu as FM } from "./float-menu";
import {
  Button as BTN,
  Switch as SW,
  Text as TXT,
  Selector as SEL,
  Slider as SLD,
  Collapsible as COL,
  Category as CAT,
} from "./ui-components";
import { TextInput as TXTIN, NumberInput as NUMIN } from "./input";
import { Logger as LOG } from "./logger";
import { EventEmitter as EE } from "./event-emitter";

// Optional: utility function to attach classes to global object for easy access
// in Frida REPL or simple scripts
export function attachToGlobal(globalObj: any = globalThis): void {
  globalObj.FloatMenu = FM;
  globalObj.Button = BTN;
  globalObj.Switch = SW;
  globalObj.Text = TXT;
  globalObj.Selector = SEL;
  globalObj.Slider = SLD;
  globalObj.Collapsible = COL;
  globalObj.Category = CAT;
  globalObj.TextInput = TXTIN;
  globalObj.NumberInput = NUMIN;
  globalObj.Logger = LOG;
  globalObj.EventEmitter = EE;
  console.log("[FloatMenu] Classes attached to global object");
}

// Optional: auto-attach in Frida environment
// Uncomment if you want automatic attachment in Frida scripts
/*
if (typeof globalThis !== 'undefined' && (globalThis as any).Java) {
    // Likely in a Frida environment with Java runtime
    attachToGlobal(globalThis);
}
*/
