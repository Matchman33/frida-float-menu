# Frida Floating Menu UI Library

A TypeScript library for creating interactive floating windows on Android devices with UI components (buttons, switches, text, selectors) that can be controlled from JavaScript. Designed for Frida instrumentation and reverse engineering.

## Features

- Create floating overlay windows using Android's `WindowManager`
- Add interactive UI components: Button, Switch, Text label, Selector (dropdown)
- Two-way data binding: JavaScript variables ↔ UI state synchronization
- Event system for UI interactions (clicks, value changes)
- Update UI components programmatically from JavaScript
- Optional log panel to display runtime logs (can be disabled for performance)
- Set window icon via base64-encoded image
- Modular, extensible architecture
- TypeScript support with full type definitions

## Requirements

- Frida (tested on Android)
- Target Android app with overlay permission (`TYPE_APPLICATION_OVERLAY`, API 26+)
- Frida-compile for TypeScript compilation (included as dev dependency)

## Installation

### As a library in your Frida project

1. Copy the `src/` directory to your project
2. Import the library in your TypeScript files:

```typescript
import { FloatMenu, Button, Switch } from './path/to/src/index';
```

### As a standalone package (conceptual)

Since this is a library, you typically include the source code in your project rather than installing from npm.

## Quick Start

### 1. Create a TypeScript file (`my-script.ts`)

```typescript
import { FloatMenu, Button, Switch, Text, Selector } from './src/index';

Java.perform(() => {
    // Create floating menu
    const menu = new FloatMenu({
        width: 300,
        height: 400,
        x: 100,
        y: 100,
        showLogs: true
    });

    menu.show();

    // Add components
    const button = new Button('myButton', 'Click Me');
    button.setOnClick(() => {
        console.log('Button clicked!');
    });
    menu.addComponent('myButton', button);

    const switchComp = new Switch('mySwitch', 'Enable Feature', false);
    switchComp.on('valueChanged', (value: boolean) => {
        console.log('Switch:', value);
    });
    menu.addComponent('mySwitch', switchComp);
});
```

### 2. Compile with frida-compile

```bash
frida-compile my-script.ts -o my-script.js -c
```

### 3. Inject into target

```bash
frida -U -f com.example.app -l my-script.js
```

## API Reference

### FloatMenu

Main class for creating and managing floating windows.

```typescript
interface TabDefinition {
    id: string;              // Unique tab identifier
    label: string;           // Display label for tab button
}

interface FloatMenuOptions {
    width?: number;           // Window width (default: 1000)
    height?: number;          // Window height (default: 900)
    x?: number;              // X position (default: 100)
    y?: number;              // Y position (default: 100)
    iconVisible?: boolean;    // Show icon initially (default: true)
    iconWidth?: number;       // Icon width (default: 200)
    iconHeight?: number;      // Icon height (default: 200)
    iconBase64?: string;      // Base64-encoded icon image (optional)
    showLogs?: boolean;       // Show log panel (default: false)
    logMaxLines?: number;     // Max lines in log panel (default: 100)
    title?: string;           // Main title text (default: "Frida Float Menu")
    subtitle?: string;        // Subtitle text (default: "Interactive Debugging Panel")
    showHeader?: boolean;     // Whether to show header (default: true)
    showFooter?: boolean;     // Whether to show footer (default: true)
    tabs?: TabDefinition[];   // Tab definitions (optional)
    activeTab?: string;       // Initially active tab ID (default: first tab or "default")
    showTabs?: boolean;       // Whether to show tab bar (default: true if tabs are defined)
}

class FloatMenu {
    constructor(options?: FloatMenuOptions);
    show(): void;                    // Display window
    hide(): void;                    // Hide and destroy window
    addComponent(id: string, component: UIComponent, tabId?: string): void;
    removeComponent(id: string): void;
    getComponent<T extends UIComponent>(id: string): T | undefined;
    setComponentValue(id: string, value: any): void;
    switchTab(tabId: string): void;  // Switch to a different tab
    getActiveTabId(): string;        // Get currently active tab ID
    on(event: string, callback: (...args: any[]) => void): void;
    off(event: string, callback: (...args: any[]) => void): void;
    setPosition(x: number, y: number): void;
    setSize(width: number, height: number): void;
    clearLogs(): void;
    showIcon(): void;                // Minimize to icon
    showMenu(): void;                // Expand to menu
    toggleView(): void;              // Toggle between icon and menu
}
```

### UI Components

All components extend `UIComponent` base class.

#### Button
```typescript
class Button extends UIComponent {
    constructor(id: string, label: string);
    setOnClick(handler: () => void): void;
    setLabel(label: string): void;
    // Emits 'click' event
}
```

#### Switch
```typescript
class Switch extends UIComponent {
    constructor(id: string, label: string, initialValue?: boolean);
    setLabel(label: string): void;
    // Emits 'valueChanged' event with boolean value
}
```

#### Text
```typescript
class Text extends UIComponent {
    constructor(id: string, content: string);
    setText(content: string): void;
}
```

#### Selector (Dropdown)
```typescript
class Selector extends UIComponent {
    constructor(id: string, items: string[], selectedIndex?: number);
    setItems(items: string[]): void;
    getSelectedIndex(): number;
    // Emits 'valueChanged' event with selected string
}
```

### Event System

Components emit events that can be listened to:

```typescript
// Component-level events
component.on('valueChanged', (value) => { /* Switch or Selector value changed */ });
component.on('click', () => { /* Button clicked */ });

// Menu forwards component events with IDs
menu.on('component:mySwitch:valueChanged', (value) => {
    console.log('Switch with ID "mySwitch" changed to:', value);
});

// Tab change events
menu.on('tabChanged', (newTabId: string, oldTabId: string) => {
    console.log(`Tab changed from ${oldTabId} to ${newTabId}`);
});
```

### Logger

Optional logging system with configurable levels:

```typescript
import { Logger, LogLevel } from './src/index';

const logger = new Logger('debug'); // 'debug' | 'info' | 'warn' | 'error' | 'none'
logger.info('Message');
logger.debug('Debug info');
```

## Examples

### Basic Example

See `example.ts` for a complete TypeScript example with all components.

### Tabbed Interface Example

Create a floating menu with multiple tabs:

```typescript
const menu = new FloatMenu({
    width: 1000,
    height: 900,
    tabs: [
        { id: "controls", label: "Controls" },
        { id: "settings", label: "Settings" },
        { id: "info", label: "Info" }
    ],
    activeTab: "controls",
    showTabs: true,
    title: "Multi-tab Menu",
    subtitle: "Organize your UI in tabs"
});

menu.show();

// Add components to specific tabs
const button = new Button("btn1", "Click Me");
menu.addComponent("btn1", button, "controls");

const switchComp = new Switch("switch1", "Enable", false);
menu.addComponent("switch1", switchComp, "settings");

// Listen for tab changes
menu.on("tabChanged", (newTabId, oldTabId) => {
    console.log(`Tab changed: ${oldTabId} -> ${newTabId}`);
});

// Switch tabs programmatically
menu.switchTab("settings");
```

### Global Attachment (for simple scripts)

If you prefer global variables instead of imports:

```typescript
import { attachToGlobal } from './src/index';
attachToGlobal(globalThis);

// Now classes are available globally
Java.perform(() => {
    const menu = new FloatMenu({ width: 300, height: 400 });
    menu.show();
});
```

### Dynamic UI Updates

```typescript
// Update UI from JavaScript
setTimeout(() => {
    menu.setComponentValue('mySwitch', true); // Turn switch on
    const textComp = menu.getComponent<Text>('myText');
    if (textComp) {
        textComp.setText('Updated!');
    }
}, 5000);
```

## Project Structure

```
frida-float-menu/
├── src/                    # Library source code
│   ├── index.ts           # Main entry point (re-exports everything)
│   ├── event-emitter.ts   # Event system
│   ├── logger.ts          # Logging utilities
│   ├── ui-components.ts   # UI component definitions
│   └── float-menu.ts      # FloatMenu main class
├── example.ts             # TypeScript usage example
├── example.js             # JavaScript usage example
├── package.json           # Package configuration
└── README.md              # This file
```

## Building and Development

### For library users
No build required - use the TypeScript source directly with frida-compile.

### For library developers
```bash
npm install                 # Install dependencies
npm run check              # Type-check without emitting
npm run build-example      # Build example script
```

## Limitations

- Requires Android API level 26+ for `TYPE_APPLICATION_OVERLAY`
- UI operations automatically scheduled on main thread
- Uses default Android widgets (no custom styling)
- Tested on Android only (not iOS)

## License

MIT

## Contributing

Contributions are welcome! Please submit issues and pull requests to enhance the library.