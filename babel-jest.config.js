module.exports = {
  presets: [
    '@babel/preset-env',
    '@babel/preset-react' // Include this if you are using React/JSX
  ],
  plugins: [
    '@babel/plugin-transform-runtime',
    'babel-plugin-transform-import-meta'
  ]
};

