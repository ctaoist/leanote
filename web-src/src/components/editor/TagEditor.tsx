import { createSignal, For, Show } from "solid-js";
import { Hash, X, Plus } from "lucide-solid";

interface TagEditorProps {
  tags: string[];
  onChange: (tags: string[]) => void;
}

export function TagEditor(props: TagEditorProps) {
  const [adding, setAdding] = createSignal(false);
  const [value, setValue] = createSignal("");

  const add = () => {
    const t = value().trim();
    if (t && !props.tags.includes(t)) props.onChange([...props.tags, t]);
    setValue("");
    setAdding(false);
  };
  const remove = (tag: string) => props.onChange(props.tags.filter((t) => t !== tag));

  return (
    <div class="flex flex-wrap items-center gap-1.5">
      <For each={props.tags}>
        {(tag) => (
          <span class="inline-flex items-center gap-1 rounded-full bg-brand-500/10 py-0.5 pl-2 pr-1 text-xs text-brand-700">
            <Hash size={11} />
            {tag}
            <button class="rounded-full p-0.5 hover:bg-brand-500/20" onClick={() => remove(tag)}>
              <X size={11} />
            </button>
          </span>
        )}
      </For>

      <Show
        when={adding()}
        fallback={
          <button
            class="inline-flex items-center gap-1 rounded-full border border-dashed border-border px-2 py-0.5 text-xs text-subtle hover:border-brand-400 hover:text-brand-600"
            onClick={() => setAdding(true)}
          >
            <Plus size={11} /> 标签
          </button>
        }
      >
        <input
          class="input h-6 w-24 px-2 text-xs"
          placeholder="标签名"
          value={value()}
          autofocus
          onInput={(e) => setValue(e.currentTarget.value)}
          onKeyDown={(e) => {
            if (e.key === "Enter") add();
            if (e.key === "Escape") setAdding(false);
          }}
          onBlur={add}
        />
      </Show>
    </div>
  );
}
