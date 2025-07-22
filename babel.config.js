// babel.config.js
export default {
  presets: [
    ['@babel/preset-env', {
      targets: { node: 'current' },
      // This is important for Jest to handle ESM correctly.
      // If you set `modules: 'auto'`, it might transform ESM to CommonJS,
      // which can cause issues with ESM imports in your tests.
      // Setting it to `false` keeps the ESM syntax intact, which is necessary for                      
      // This is a common option to disable transformation of import.meta when using webpack/Node.js environments
      // It might not be directly applicable for bare Jest, but worth trying if it's the culprit.
      // Usually, it's used with `modules: false` to keep ESM syntax.
      bugfixes: true, // Recommended for newer Babel versions
    }],
  ],
  // Add plugins if necessary, but generally preset-env handles it.
};