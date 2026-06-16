import { createEffect, onCleanup, onMount } from "solid-js";
import { EditorView, keymap, lineNumbers, highlightActiveLine } from "@codemirror/view";
import { EditorState, Compartment } from "@codemirror/state";
import { defaultKeymap, history, historyKeymap, indentWithTab } from "@codemirror/commands";
import { languages } from "@codemirror/language-data";
import { LanguageDescription, syntaxHighlighting, HighlightStyle, bracketMatching } from "@codemirror/language";
import { tags as t } from "@lezer/highlight";

// Token colors use the same --cm-* CSS variables as the markdown editor's code
// blocks (defined in app.css, light/dark aware) so theme-file highlighting
// matches the rest of the app.
const codeHighlight = HighlightStyle.define([
  { tag: [t.comment, t.lineComment, t.blockComment, t.docComment], color: "var(--cm-comment)", fontStyle: "italic" },
  {
    tag: [t.keyword, t.controlKeyword, t.operatorKeyword, t.definitionKeyword, t.moduleKeyword, t.modifier, t.self],
    color: "var(--cm-keyword)",
  },
  { tag: [t.string, t.special(t.string), t.character], color: "var(--cm-string)" },
  { tag: [t.number, t.integer, t.float, t.bool, t.atom, t.null], color: "var(--cm-number)" },
  { tag: [t.function(t.variableName), t.function(t.propertyName)], color: "var(--cm-function)" },
  { tag: [t.typeName, t.className, t.namespace, t.constant(t.variableName)], color: "var(--cm-class)" },
  { tag: [t.propertyName, t.attributeName, t.tagName, t.labelName], color: "var(--cm-tag)" },
  { tag: [t.variableName, t.regexp, t.escape], color: "var(--cm-variable)" },
  {
    tag: [t.operator, t.punctuation, t.bracket, t.angleBracket, t.derefOperator, t.separator],
    color: "var(--cm-punct)",
  },
]);

const editorTheme = EditorView.theme({
  "&": { height: "100%", backgroundColor: "transparent", color: "rgb(var(--c-fg))" },
  ".cm-scroller": {
    fontFamily: "var(--font-mono, ui-monospace, monospace)",
    fontSize: "12.5px",
    lineHeight: "1.6",
    padding: "8px 4px",
  },
  "&.cm-focused": { outline: "none" },
  ".cm-content": { caretColor: "rgb(var(--c-accent))" },
  ".cm-cursor": { borderLeftColor: "rgb(var(--c-accent))" },
  ".cm-gutters": { backgroundColor: "transparent", color: "rgb(var(--c-subtle))", border: "none" },
  ".cm-activeLine": { backgroundColor: "rgb(var(--c-fg) / 0.03)" },
  ".cm-activeLineGutter": { backgroundColor: "rgb(var(--c-fg) / 0.04)" },
  ".cm-selectionBackground, ::selection": { backgroundColor: "rgb(var(--c-accent) / 0.18)" },
  ".cm-placeholder": { color: "rgb(var(--c-subtle))" },
});

/**
 * CodeMirror 6 code editor for theme files. Language support is chosen from the
 * filename extension via @codemirror/language-data (lazy-loaded), so .html/.css/
 * .js/.json get proper syntax highlighting. Controlled via value/onChange.
 */
export function ThemeCodeEditor(props: {
  value: string;
  filename: string;
  editable?: boolean;
  onChange: (v: string) => void;
}) {
  let host!: HTMLDivElement;
  let view: EditorView | undefined;
  let applying = false; // guard so programmatic doc replacement doesn't echo onChange
  const langComp = new Compartment();
  const editComp = new Compartment();

  const loadLanguage = (filename: string) => {
    if (!view) return;
    const desc = filename ? LanguageDescription.matchFilename(languages, filename) : null;
    if (!desc) {
      view.dispatch({ effects: langComp.reconfigure([]) });
      return;
    }
    void desc.load().then((support) => {
      view?.dispatch({ effects: langComp.reconfigure(support) });
    });
  };

  onMount(() => {
    view = new EditorView({
      parent: host,
      state: EditorState.create({
        doc: props.value ?? "",
        extensions: [
          lineNumbers(),
          highlightActiveLine(),
          history(),
          bracketMatching(),
          keymap.of([...defaultKeymap, ...historyKeymap, indentWithTab]),
          langComp.of([]),
          editComp.of(EditorView.editable.of(props.editable ?? true)),
          syntaxHighlighting(codeHighlight),
          EditorView.lineWrapping,
          editorTheme,
          EditorView.updateListener.of((u) => {
            if (u.docChanged && !applying) props.onChange(u.state.doc.toString());
          }),
        ],
      }),
    });
    loadLanguage(props.filename);
  });

  // external value changes (switching files) → replace doc without echoing
  createEffect(() => {
    const v = props.value ?? "";
    if (!view) return;
    if (v !== view.state.doc.toString()) {
      applying = true;
      view.dispatch({ changes: { from: 0, to: view.state.doc.length, insert: v } });
      applying = false;
    }
  });

  // filename change → swap language
  createEffect(() => {
    const fn = props.filename;
    if (view) loadLanguage(fn);
  });

  // editable toggle
  createEffect(() => {
    view?.dispatch({ effects: editComp.reconfigure(EditorView.editable.of(props.editable ?? true)) });
  });

  onCleanup(() => view?.destroy());

  return <div ref={host} class="h-full w-full overflow-auto" />;
}
