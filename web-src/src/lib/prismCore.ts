// prismjs language components (imported for side effects in ./prism) are written
// as `(function (Prism) { Prism.languages.x = … }(Prism))` — they reference a
// *global* `Prism` and do NOT import the core themselves. Prism core does set
// `window.Prism`, but under the production rollup/minify build that assignment
// isn't reliably visible to the bundled component modules, yielding a runtime
// "Prism is not defined" in the vendor-prism chunk.
//
// Fix: import the core here and pin it on globalThis, then import this module
// FIRST in ./prism so the global exists before any component module evaluates
// (ES module evaluation order is preserved by the bundler).
import Prism from "prismjs";

(globalThis as unknown as { Prism: typeof Prism }).Prism = Prism;

export default Prism;
