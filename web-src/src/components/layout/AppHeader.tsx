import { Show, createSignal } from "solid-js";
import { useNavigate } from "@solidjs/router";
import {
  PanelLeft,
  Search,
  FilePlus2,
  Hash,
  Check,
  Loader2,
  LogOut,
  Moon,
  Sun,
  UserRound,
  Images,
  Settings,
} from "lucide-solid";
import { appState, actions } from "../../state/appStore";
import { authApi } from "../../api/endpoints";
import { isMobile } from "../../lib/responsive";
import { BrandMark } from "../Brand";
import { IconButton } from "../ui/Button";
import { Avatar } from "../ui/Avatar";
import { Dropdown, MenuItem, MenuDivider } from "../ui/Dropdown";
import { isDark, toggleDark } from "../../lib/theme";
import { avatarUrl } from "../../lib/url";
import { AccountModal } from "../account/AccountModal";
import { AlbumModal } from "../album/AlbumModal";

export function AppHeader() {
  const navigate = useNavigate();
  const [search, setSearch] = createSignal("");
  const [showAccount, setShowAccount] = createSignal(false);
  const [showAlbum, setShowAlbum] = createSignal(false);
  let searchTimer: ReturnType<typeof setTimeout> | undefined;

  const onSearchInput = (v: string) => {
    setSearch(v);
    if (searchTimer) clearTimeout(searchTimer);
    searchTimer = setTimeout(() => void actions.search(v), 350);
  };

  const logout = async () => {
    try {
      await authApi.logout();
    } catch {
      /* ignore */
    }
    navigate("/login", { replace: true });
  };

  return (
    <header class="flex h-14 shrink-0 items-center gap-2 border-b border-border bg-surface px-3">
      <IconButton label="折叠/展开侧栏" onClick={() => (isMobile() ? actions.toggleNbDrawer() : actions.toggleLeft())}>
        <PanelLeft size={18} />
      </IconButton>

      <a href="/" class="mr-1 hidden sm:block">
        <BrandMark size={18} />
      </a>

      {/* 搜索 */}
      <div class="relative w-44 sm:w-64">
        <Search size={15} class="pointer-events-none absolute left-3 top-1/2 -translate-y-1/2 text-subtle" />
        <input
          class="input h-9 pl-9 pr-3 text-sm"
          placeholder="搜索笔记…"
          value={search()}
          onInput={(e) => onSearchInput(e.currentTarget.value)}
        />
      </div>

      {/* 新建 */}
      <div class="ml-1 flex items-center overflow-hidden rounded-lg border border-border">
        <button
          class="flex h-9 items-center gap-1.5 px-2.5 text-sm font-medium text-fg transition-colors hover:bg-brand-500/10 hover:text-brand-600 sm:px-3"
          onClick={() => void actions.createNote(false)}
          title="新建富文本笔记"
        >
          <FilePlus2 size={15} /> <span class="hidden sm:inline">新建</span>
        </button>
        <div class="hidden h-5 w-px bg-border sm:block" />
        <button
          class="hidden h-9 items-center gap-1.5 px-3 text-sm font-medium text-fg transition-colors hover:bg-brand-500/10 hover:text-brand-600 sm:flex"
          onClick={() => void actions.createNote(true)}
          title="新建 Markdown 笔记"
        >
          <Hash size={15} /> Markdown
        </button>
      </div>

      <div class="flex-1" />

      {/* 保存状态 */}
      <div class="mr-1 hidden w-20 items-center justify-end text-xs text-subtle sm:flex">
        <Show when={appState.saving}>
          <span class="flex items-center gap-1">
            <Loader2 size={13} class="animate-spin" /> 保存中
          </span>
        </Show>
        <Show when={!appState.saving && !appState.dirty && appState.currentNote}>
          <span class="flex items-center gap-1 text-brand-600">
            <Check size={13} /> 已保存
          </span>
        </Show>
      </div>

      {/* 用户菜单 */}
      <Dropdown
        align="right"
        width="200px"
        trigger={({ toggle }) => (
          <button
            class="flex items-center gap-2 rounded-lg px-1.5 py-1 transition-colors hover:bg-black/5 dark:hover:bg-white/5"
            onClick={toggle}
          >
            <Avatar src={avatarUrl(appState.user?.Logo)} name={appState.user?.Username} size={28} />
            <span class="hidden max-w-[120px] truncate text-sm font-medium text-fg sm:block">
              {appState.user?.Username ?? "我的账户"}
            </span>
          </button>
        )}
      >
        {(close) => (
          <>
            <div class="px-3 py-2">
              <div class="truncate text-sm font-medium text-fg">{appState.user?.Username ?? "未登录"}</div>
              <div class="truncate text-xs text-subtle">{appState.user?.Email ?? ""}</div>
            </div>
            <MenuDivider />
            <MenuItem icon={<UserRound size={15} />} onClick={() => { close(); setShowAccount(true); }}>
              账户设置
            </MenuItem>
            <MenuItem icon={<Images size={15} />} onClick={() => { close(); setShowAlbum(true); }}>
              图片库
            </MenuItem>
            <MenuItem
              icon={isDark() ? <Sun size={15} /> : <Moon size={15} />}
              onClick={() => toggleDark()}
            >
              {isDark() ? "浅色模式" : "深色模式"}
            </MenuItem>
            <Show when={appState.user}>
              <MenuDivider />
              <MenuItem icon={<Settings size={15} />} onClick={() => { close(); navigate("/admin"); }}>
                设置
              </MenuItem>
            </Show>
            <MenuDivider />
            <MenuItem icon={<LogOut size={15} />} danger onClick={() => { close(); void logout(); }}>
              退出登录
            </MenuItem>
          </>
        )}
      </Dropdown>

      <AccountModal open={showAccount()} onClose={() => setShowAccount(false)} />
      <AlbumModal open={showAlbum()} onClose={() => setShowAlbum(false)} />
    </header>
  );
}
