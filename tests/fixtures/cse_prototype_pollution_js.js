/**
 * CWE-1321: Prototype Pollution in JavaScript
 * Recursive merge without __proto__ filtering allows object prototype modification.
 */

function deepMerge(target, source) {
  // Vulnerable: no check for __proto__, constructor, or prototype keys
  for (const key in source) {
    if (typeof source[key] === "object" && source[key] !== null) {
      if (!target[key]) target[key] = {};
      deepMerge(target[key], source[key]);
    } else {
      target[key] = source[key];
    }
  }
  return target;
}

function setNestedValue(obj, path, value) {
  // Vulnerable: path can contain __proto__
  const keys = path.split(".");
  let current = obj;
  for (let i = 0; i < keys.length - 1; i++) {
    if (!current[keys[i]]) current[keys[i]] = {};
    current = current[keys[i]];
  }
  current[keys[keys.length - 1]] = value;
}

function processConfig(userConfig) {
  const defaults = { theme: "light", lang: "en" };
  // Merges user-supplied config into defaults
  return deepMerge(defaults, JSON.parse(userConfig));
}

// Demonstration
const malicious = '{"__proto__": {"isAdmin": true}}';
const config = processConfig(malicious);
console.log("Config:", config);
console.log("isAdmin on empty object:", {}.isAdmin);

module.exports = { deepMerge, setNestedValue, processConfig };
