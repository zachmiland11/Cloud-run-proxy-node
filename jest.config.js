export default {
  // This tells Jest to transform files ending with .js, .jsx, .ts, or .tsx
  // using babel-jest.
  transform: {
    '^.+\\.[tj]sx?$': 'babel-jest',
  },
  // Ensure that node_modules are not ignored if they also use ESM and need transpilation.
  // The (?!...) is a negative lookahead, meaning "match node_modules UNLESS it's one of these".
  // You might need to adjust this if specific node_modules need transformation.
  transformIgnorePatterns: [
    '/node_modules/(?!(your-esm-dependency-here|another-one)/)',
  ],
  // If your project uses ES Modules (import/export), you might need to
  // explicitly tell Jest how to resolve them.
  // This is often implicitly handled by Babel, but can be useful.
  // preset: 'ts-jest/presets/js-with-babel-esm', // if using TypeScript
  // If you added "type": "module" to your package.json, Jest should handle ESM correctly.
};

