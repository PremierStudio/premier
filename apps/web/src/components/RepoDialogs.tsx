import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { api, cloneUrls, repoNameError, type Repo, type User } from "../api";
import { ErrorNote, Field, PRIMARY_BTN, SECONDARY_BTN, useAction } from "./forms";
import { BrandIcon, detectGitHost } from "./BrandIcons";
import { IconCheck, IconClock, IconClose, IconCopy, IconRefresh, IconTerminal } from "./Icons";

const FOCUSABLE = 'a[href], button:not([disabled]), input:not([disabled]), select:not([disabled]), textarea:not([disabled])';

/** Returns an error for a non-empty import URL the server would reject, else null. */
function importUrlError(value: string): string | null {
  try {
    if (new URL(value).protocol === "https:") return null;
  } catch {
    // falls through to the message
  }
  return "The import URL must start with https://";
}

/** Last path segment of an import URL as a lowercase repo slug ("https://github.com/o/My-App.git" -> "my-app"). */
function slugFromUrl(value: string): string {
  const last = value.trim().replace(/[?#].*$/, "").replace(/\/+$/, "").split("/").pop() ?? "";
  return last
    .replace(/\.git$/i, "")
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/g, "-")
    .replace(/^[-._]+|[-._]+$/g, "")
    .slice(0, 63);
}

/** Owner-only "New repository" modal. Can't be dismissed while the create/import request runs. */
export function NewRepoDialog({
  existing,
  onClose,
  onCreated,
  initialMode = "new",
}: {
  existing: Repo[];
  onClose: () => void;
  onCreated: (repo: Repo & { imported_policy?: boolean }) => void;
  initialMode?: "new" | "import";
}) {
  const importMode = initialMode === "import";
  const [name, setName] = useState("");
  const [description, setDescription] = useState("");
  const [importUrl, setImportUrl] = useState("");
  const [nameTouched, setNameTouched] = useState(false);
  const [nameManual, setNameManual] = useState(false);
  const action = useAction();
  const titleId = useId();
  const panelRef = useRef<HTMLDivElement>(null);
  const url = importUrl.trim();
  const importing = action.pending && url !== "";
  // Shown after the field is first left, then live as it is edited.
  const nameProblem = nameTouched
    ? (repoNameError(name) ??
      (existing.some((r) => r.name === name) ? `A repository named “${name}” already exists.` : null))
    : null;

  // Hand focus back to whatever opened the dialog.
  useEffect(() => {
    const opener = document.activeElement as HTMLElement | null;
    return () => opener?.focus?.();
  }, []);

  // Disabling the form drops focus to <body>; park it on the panel so the trap and Escape guard hold.
  useEffect(() => {
    if (action.pending) panelRef.current?.focus();
  }, [action.pending]);

  const close = () => {
    if (!action.pending) onClose();
  };

  const onKeyDown = (e: KeyboardEvent) => {
    // Keeps the Studio's global shortcuts (1–7, g-chords, palette) from firing behind the modal.
    e.stopPropagation();
    if (e.key === "Escape") {
      close();
    } else if (e.key === "Tab") {
      const items = panelRef.current?.querySelectorAll<HTMLElement>(FOCUSABLE);
      if (!items || items.length === 0) {
        e.preventDefault(); // everything is disabled mid-import: keep focus on the panel
        return;
      }
      const first = items[0];
      const last = items[items.length - 1];
      if (e.shiftKey && document.activeElement === first) {
        e.preventDefault();
        last.focus();
      } else if (!e.shiftKey && document.activeElement === last) {
        e.preventDefault();
        first.focus();
      }
    }
  };

  const submit = (e: FormEvent) => {
    e.preventDefault();
    const problem =
      repoNameError(name) ??
      (existing.some((r) => r.name === name) ? `A repository named “${name}” already exists.` : null) ??
      (url ? importUrlError(url) : null);
    if (problem) {
      action.setError(problem);
      return;
    }
    void action.run(async () =>
      onCreated(
        await api.createRepo({
          name,
          description: description.trim() || undefined,
          import_url: url || undefined,
        }),
      ),
    );
  };

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center overflow-y-auto bg-[#04060d]/80 px-4 py-10 backdrop-blur-sm sm:pt-24"
      onMouseDown={(e) => {
        if (e.target === e.currentTarget) close();
      }}
    >
      <div
        ref={panelRef}
        role="dialog"
        aria-modal="true"
        aria-labelledby={titleId}
        tabIndex={-1}
        onKeyDown={onKeyDown}
        className="pr-elevated w-full max-w-md overflow-hidden rounded-2xl focus:outline-none"
      >
        <div className="flex items-center justify-between gap-3 border-b border-white/[0.08] px-4 py-3">
          <div className="flex items-center gap-2.5">
            <span className="pr-icon-tile inline-flex h-7 w-7 items-center justify-center rounded-lg">
              <BrandIcon name={importMode || url ? detectGitHost(url) : "git"} className="h-4 w-4" />
            </span>
            <h2 id={titleId} className="text-[14px] font-semibold text-[#f3f6fd]">
              {importMode ? "Import repository" : "New repository"}
            </h2>
          </div>
          <button
            type="button"
            onClick={close}
            disabled={action.pending}
            aria-label="Close"
            className="rounded-lg p-1.5 text-[#98a8c4] hover:bg-white/[0.06] hover:text-white disabled:opacity-40"
          >
            <IconClose className="h-4 w-4" />
          </button>
        </div>

        <form onSubmit={submit} noValidate className="space-y-3.5 p-4">
          {importMode && (
            <Field
              label="Repository URL (HTTPS)"
              name="repo_import_url"
              autoFocus
              type="url"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              disabled={action.pending}
              placeholder="https://github.com/owner/project.git"
              hint="GitHub, GitLab, Bitbucket, or any HTTPS Git remote."
              className="font-mono"
              value={importUrl}
              onChange={(e) => {
                const value = e.target.value;
                setImportUrl(value);
                if (!nameManual) setName(slugFromUrl(value));
              }}
            />
          )}
          <Field
            label="Name"
            name="repo_name"
            autoFocus={!importMode}
            autoComplete="off"
            autoCapitalize="none"
            spellCheck={false}
            required
            maxLength={63}
            disabled={action.pending}
            hint='Lowercase letters, digits, ".", "-" and "_". Used in URLs and git remotes.'
            className={`font-mono ${nameProblem ? "border-[#f27c7c]/60" : ""}`}
            aria-invalid={nameProblem ? true : undefined}
            value={name}
            onBlur={() => setNameTouched(true)}
            onChange={(e) => {
              setNameManual(true);
              setName(e.target.value.toLowerCase());
            }}
          />
          {nameProblem && (
            <p role="alert" className="-mt-2 text-[13px] text-[#f27c7c]">
              {nameProblem}
            </p>
          )}
          <Field
            label="Description"
            name="repo_description"
            autoComplete="off"
            maxLength={500}
            disabled={action.pending}
            hint="Optional."
            value={description}
            onChange={(e) => setDescription(e.target.value)}
          />
          {!importMode && (
            <Field
              label="Import from URL (HTTPS)"
              name="repo_import_url"
              type="url"
              inputMode="url"
              autoComplete="off"
              autoCapitalize="none"
              spellCheck={false}
              disabled={action.pending}
              placeholder="https://github.com/owner/project.git"
              hint="Optional. Leave empty to start with an empty repository."
              className="font-mono"
              value={importUrl}
              onChange={(e) => {
                const value = e.target.value;
                setImportUrl(value);
                if (!nameManual) setName(slugFromUrl(value));
              }}
            />
          )}

          {importing && (
            <div
              role="status"
              className="flex items-start gap-2 rounded-xl border border-[#9ec0f5]/30 bg-[#7f95f8]/10 px-3 py-2 text-[13.5px] leading-relaxed text-[#9ec0f5]"
            >
              <IconClock className="mt-px h-4 w-4 shrink-0" />
              <span>Importing. This can take a few minutes for a large project; keep this tab open.</span>
            </div>
          )}
          <ErrorNote message={action.error} />

          <div className="flex flex-wrap justify-end gap-2">
            <button type="button" onClick={close} disabled={action.pending} className={SECONDARY_BTN}>
              Cancel
            </button>
            <button type="submit" disabled={action.pending || !name} className={PRIMARY_BTN}>
              {importing ? "Importing…" : action.pending ? "Creating…" : url ? "Import repository" : "Create repository"}
            </button>
          </div>
        </form>
      </div>
    </div>
  );
}

/** Code view for a repository with no commits: how to push an existing project into it. */
export function EmptyRepoPanel({
  user,
  repo,
  onRefresh,
  title = "This repository is empty",
}: {
  title?: string;
  user: User;
  repo: Repo;
  onRefresh: () => void;
}) {
  const [copied, setCopied] = useState<number | null>(null);
  const isOwner = user.role === "owner";
  const remote = cloneUrls(user.username, repo.name).auth;
  const branch = repo.default_branch ?? "main";
  const commands = [
    `git remote add premier ${remote}`,
    `git push -u premier ${branch}`,
  ];

  const copy = (idx: number) => {
    navigator.clipboard?.writeText(commands[idx]).catch(() => {});
    setCopied(idx);
    setTimeout(() => setCopied(null), 1600);
  };

  return (
    <div className="min-h-0 flex-1 overflow-y-auto p-3 sm:p-4 xl:p-5">
      <section className="pr-surface mx-auto max-w-2xl space-y-3.5 rounded-2xl p-4 sm:p-5">
        <h2 className="inline-flex items-center gap-2 text-[14px] font-semibold text-[#f3f6fd]">
          <IconTerminal className="h-[18px] w-[18px] text-[#9ec0f5]" />
          <span>{isOwner ? title : "This repository is empty"}</span>
        </h2>
        {isOwner ? (
          <>
            <p className="text-[14px] leading-relaxed text-[#b6c3db]">
              <code className="text-[#dce4f5]">{repo.name}</code> has no commits yet. Push an existing
              project from its folder. Git asks for a password: use an access token from Settings.
            </p>
            <ul className="space-y-2">
              {commands.map((cmd, idx) => (
                <li key={cmd} className="flex items-center gap-2">
                  <code className="pr-well min-w-0 flex-1 select-all break-all rounded-xl px-3 py-2 text-[13.5px] text-[#f3f6fd]">
                    {cmd}
                  </code>
                  <button
                    type="button"
                    onClick={() => copy(idx)}
                    aria-label={`Copy command: ${cmd}`}
                    className={`${SECONDARY_BTN} shrink-0`}
                  >
                    {copied === idx ? (
                      <IconCheck className="h-4 w-4 text-[#5bdba2]" />
                    ) : (
                      <IconCopy className="h-4 w-4 text-[#a6b5cf]" />
                    )}
                    <span>{copied === idx ? "Copied" : "Copy"}</span>
                  </button>
                </li>
              ))}
            </ul>
            <button type="button" onClick={onRefresh} className={SECONDARY_BTN}>
              <IconRefresh className="h-4 w-4 text-[#a6b5cf]" />
              <span>I've pushed, refresh</span>
            </button>
          </>
        ) : (
          <>
            <p className="text-[14px] leading-relaxed text-[#b6c3db]">
              This repository has no commits visible to your account yet.
            </p>
            <button type="button" onClick={onRefresh} className={SECONDARY_BTN}>
              <IconRefresh className="h-4 w-4 text-[#a6b5cf]" />
              <span>Check again</span>
            </button>
          </>
        )}
      </section>
    </div>
  );
}
