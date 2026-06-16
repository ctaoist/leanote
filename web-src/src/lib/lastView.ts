// Remembers the last-viewed notebook + note per user so reopening the notes page
// restores where you were instead of always jumping to the first note. Stored in
// localStorage (best-effort; private mode / quota errors are ignored).

const key = (userId: string) => `leanote:lastView:${userId || "anon"}`;

export interface LastView {
  notebookId: string;
  noteId: string;
}

export function saveLastView(userId: string, v: LastView): void {
  try {
    localStorage.setItem(key(userId), JSON.stringify(v));
  } catch {
    /* ignore: storage unavailable */
  }
}

export function loadLastView(userId: string): LastView | null {
  try {
    const raw = localStorage.getItem(key(userId));
    if (!raw) return null;
    const v = JSON.parse(raw) as Partial<LastView>;
    if (v && typeof v.notebookId === "string") {
      return { notebookId: v.notebookId, noteId: typeof v.noteId === "string" ? v.noteId : "" };
    }
  } catch {
    /* ignore: corrupt value */
  }
  return null;
}
