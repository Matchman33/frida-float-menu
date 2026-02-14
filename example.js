// Example usage of FloatMenu library for Frida
// This script demonstrates two ways to use the library:

// Method 1: Import as module (when using frida-compile with TypeScript)
// In a TypeScript file, you would use:
// import { FloatMenu, Button, Switch, Text, Selector, attachToGlobal } from './src/index';

// Method 2: Global attachment (simple scripts)
// First, you need to inject the library, then call attachToGlobal()
// This example assumes the library is already loaded

// Wait for Java runtime to be ready
Java.perform(() => {
    console.log('Java runtime ready, creating floating menu...');

    // If using as a module (Method 1), classes would already be available
    // If using global attachment (Method 2), first attach to global:
    // attachToGlobal(globalThis);

    // For this example, we assume the library has been attached to global
    // Check if classes are available
    if (typeof FloatMenu === 'undefined') {
        console.error('FloatMenu library not loaded! Please inject the library first.');
        console.error('If using as a module, make sure to import it.');
        console.error('If using global attachment, call attachToGlobal(globalThis) first.');
        return;
    }

    // Create a floating menu with logs enabled
    const menu = new FloatMenu({
        width: 350,
        height: 500,
        x: 50,
        y: 50,
        showLogs: true,
        // iconBase64: '...' // optional base64 icon
    });

    menu.show();

    // Add a button
    const btn = new Button('myButton', 'Click Me');
    btn.setOnClick(() => {
        console.log('Button clicked!');
        menu.setComponentValue('mySwitch', true); // Turn on switch
    });
    menu.addComponent('btn', btn);

    // Add a switch
    const sw = new Switch('mySwitch', 'Enable Feature', false);
    sw.on('valueChanged', (value) => {
        console.log('Switch changed to:', value);
        if (value) {
            txt.setText('Feature enabled!');
        } else {
            txt.setText('Feature disabled');
        }
    });
    menu.addComponent('sw', sw);

    // Add text label
    const txt = new Text('myText', 'Hello from Frida!');
    menu.addComponent('txt', txt);

    // Add selector (dropdown)
    const selector = new Selector('mySelector', ['Option A', 'Option B', 'Option C'], 0);
    selector.on('valueChanged', (value) => {
        console.log('Selected:', value);
        txt.setText('Selected: ' + value);
    });
    menu.addComponent('selector', selector);

    // Listen to component events via menu
    menu.on('component:mySwitch:valueChanged', (value) => {
        console.log('Menu event: switch value changed to', value);
    });

    // Update UI from JS after 5 seconds
    setTimeout(() => {
        console.log('Updating UI from JS...');
        menu.setComponentValue('mySwitch', true);
        txt.setText('Updated via JS timer');
        selector.setItems(['New Option 1', 'New Option 2', 'New Option 3']);
    }, 5000);

    // Hide menu after 15 seconds (optional)
    setTimeout(() => {
        menu.hide();
        console.log('Menu hidden');
    }, 15000);

    console.log('Floating menu setup complete. Interact with the UI.');
});

// Usage notes for developers:
// 1. As a module (recommended for TypeScript projects):
//    - Create a .ts file and import: import { FloatMenu, Button } from 'frida-float-menu';
//    - Compile with frida-compile: frida-compile your-script.ts -o output.js
//    - Inject output.js into target
//
// 2. As a global library:
//    - First inject the library (compile it first if needed)
//    - Call attachToGlobal() to make classes available globally
//    - Use classes as shown above
//
// 3. Direct import in JavaScript (if using ES modules):
//    - Not recommended for Frida due to module system constraints
//    - Better to use TypeScript with frida-compile