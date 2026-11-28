/// <reference types="vite/client" />

export type MonacoModule = typeof import("monaco-editor");

export const PREMIER_MONACO_THEME = "premier-obsidian";
export const PREMIER_ACCESS_TOML_LANGUAGE = "premier-access-toml";
export const PREMIER_MARKER_OWNER = "premier-policy";

export interface MonacoMarkerInput {
  startLineNumber: number;
  startColumn: number;
  endLineNumber: number;
  endColumn: number;
  message: string;
  severity: "error" | "warning" | "info";
}

export interface UnifiedPatchSides {
  original: string;
  modified: string;
  hasChanges: boolean;
  /** 1-based real file line number per Monaco original line (0 for synthetic separator lines). */
  originalLineMap: number[];
  /** 1-based real file line number per Monaco modified line (0 for synthetic separator lines). */
  modifiedLineMap: number[];
}

type WorkerConstructor = new () => Worker;

interface MonacoGlobalScope {
  MonacoEnvironment?: {
    getWorker?: (workerId: string, label: string) => Worker | Promise<Worker>;
  };
}

let monacoPromise: Promise<MonacoModule> | null = null;
let environmentConfigured = false;
let customizationsRegistered = false;

/**
 * Lazy singleton loader for the offline-bundled Monaco Editor.
 * Configures Vite `?worker` web workers (zero CDN / external requests) so only
 * `editor.worker` is loaded up front and heavy language workers (such as the
 * ~7 MB TypeScript worker) are dynamically imported on demand when a buffer
 * actually opens in that language.
 */
export function loadMonaco(): Promise<MonacoModule> {
  if (monacoPromise) return monacoPromise;

  monacoPromise = (async () => {
    const editorWorkerMod = await import("monaco-editor/editor/editor.worker?worker");

    if (!environmentConfigured) {
      const EditorWorker: WorkerConstructor = editorWorkerMod.default;
      const workerCache = new Map<string, Promise<WorkerConstructor>>();

      const loadLanguageWorker = (
        key: string,
        loader: () => Promise<{ default: WorkerConstructor }>,
      ): Promise<Worker> => {
        let pending = workerCache.get(key);
        if (!pending) {
          pending = loader().then((mod) => mod.default);
          workerCache.set(key, pending);
        }
        return pending.then((WorkerCtor) => new WorkerCtor());
      };

      (self as unknown as MonacoGlobalScope).MonacoEnvironment = {
        getWorker(_workerId: string, label: string): Worker | Promise<Worker> {
          switch (label) {
            case "json":
              return loadLanguageWorker(
                "json",
                () => import("monaco-editor/language/json/json.worker?worker"),
              );
            case "css":
            case "scss":
            case "less":
              return loadLanguageWorker(
                "css",
                () => import("monaco-editor/language/css/css.worker?worker"),
              );
            case "html":
            case "handlebars":
            case "razor":
              return loadLanguageWorker(
                "html",
                () => import("monaco-editor/language/html/html.worker?worker"),
              );
            case "typescript":
            case "javascript":
              return loadLanguageWorker(
                "typescript",
                () => import("monaco-editor/language/typescript/ts.worker?worker"),
              );
            default:
              return new EditorWorker();
          }
        },
      };
      environmentConfigured = true;
    }

    const monaco = await import("monaco-editor");

    if (!customizationsRegistered) {
      configureTypeScriptDefaults(monaco);
      registerPremierTheme(monaco);
      registerTomlLanguage(monaco);
      registerPremierAccessTomlLanguage(monaco);
      customizationsRegistered = true;
    }

    return monaco;
  })().catch((err) => {
    monacoPromise = null;
    throw err;
  });

  return monacoPromise;
}

/**
 * Single-file previews and diff panes do not have `node_modules` or a full
 * `tsconfig.json` mounted in Monaco's TS worker. Disable semantic type errors
 * while keeping syntax validation + JSX support enabled so code previews never
 * spam false red squiggles on valid imports or JSX.
 */
function configureTypeScriptDefaults(monaco: MonacoModule): void {
  const diagnosticsOptions = {
    noSemanticValidation: true,
    noSyntaxValidation: false,
  };
  const compilerOptions = {
    jsx: monaco.typescript.JsxEmit.Preserve,
    target: monaco.typescript.ScriptTarget.ESNext,
    moduleResolution: monaco.typescript.ModuleResolutionKind.NodeJs,
    allowNonTsExtensions: true,
    allowJs: true,
  };

  monaco.typescript.typescriptDefaults.setDiagnosticsOptions(diagnosticsOptions);
  monaco.typescript.javascriptDefaults.setDiagnosticsOptions(diagnosticsOptions);
  monaco.typescript.typescriptDefaults.setCompilerOptions(compilerOptions);
  monaco.typescript.javascriptDefaults.setCompilerOptions(compilerOptions);
}

function registerPremierTheme(monaco: MonacoModule): void {
  monaco.editor.defineTheme(PREMIER_MONACO_THEME, {
    base: "vs-dark",
    inherit: true,
    rules: [
      // Core vibrant obsidian syntax tokens
      { token: "keyword", foreground: "c68cff" },
      { token: "keyword.control", foreground: "d2a8ff" },
      { token: "keyword.flow", foreground: "d2a8ff" },
      { token: "storage", foreground: "d2a8ff" },
      { token: "storage.type", foreground: "d2a8ff" },
      { token: "function", foreground: "79b8ff" },
      { token: "entity.name.function", foreground: "79b8ff" },
      { token: "support.function", foreground: "79b8ff" },
      { token: "type", foreground: "4fd1c5" },
      { token: "type.identifier", foreground: "4fd1c5" },
      { token: "entity.name.type", foreground: "4fd1c5" },
      { token: "entity.name.class", foreground: "4fd1c5" },
      { token: "support.type", foreground: "4fd1c5" },
      { token: "support.class", foreground: "4fd1c5" },
      { token: "string", foreground: "6ee7b7" },
      { token: "string.quoted", foreground: "6ee7b7" },
      { token: "string.value", foreground: "6ee7b7" },
      { token: "string.escape", foreground: "5eead4" },
      { token: "regexp", foreground: "5eead4" },
      { token: "number", foreground: "f6ad55" },
      { token: "number.float", foreground: "f6ad55" },
      { token: "number.hex", foreground: "f6ad55" },
      { token: "constant", foreground: "f6ad55" },
      { token: "constant.numeric", foreground: "f6ad55" },
      { token: "constant.language", foreground: "f6ad55" },
      { token: "comment", foreground: "6b7c9c", fontStyle: "italic" },
      { token: "comment.doc", foreground: "6b7c9c", fontStyle: "italic" },
      { token: "operator", foreground: "93c5fd" },
      { token: "delimiter", foreground: "93a6c8" },
      { token: "tag", foreground: "f472b6" },
      { token: "metatag", foreground: "f472b6" },
      { token: "attribute.name", foreground: "9ec0f5" },
      { token: "annotation", foreground: "9ec0f5" },
      { token: "key", foreground: "a5d6ff" },
      { token: "string.key", foreground: "a5d6ff" },
      { token: "string.key.json", foreground: "a5d6ff" },
      { token: "string.value.json", foreground: "6ee7b7" },
      { token: "property", foreground: "a5d6ff" },
      { token: "variable", foreground: "dce4f5" },
      { token: "invalid", foreground: "ff7b7b" },

      // Custom Premier `.access.toml` semantic tokens
      { token: "premier.effect.deny", foreground: "ff7b7b", fontStyle: "bold" },
      { token: "premier.effect.allow", foreground: "5bdba2", fontStyle: "bold" },
      { token: "premier.section", foreground: "c68cff", fontStyle: "bold" },
      { token: "premier.capability", foreground: "4fd1c5", fontStyle: "bold" },
      { token: "premier.principal", foreground: "f6ad55" },
      { token: "premier.key", foreground: "9ec0f5" },
    ],
    colors: {
      "editor.background": "#090d18",
      "editorGutter.background": "#090d18",
      "editor.foreground": "#dce4f5",
      "editorLineNumber.foreground": "#6b7b98",
      "editorLineNumber.activeForeground": "#9ec0f5",
      "editorCursor.foreground": "#79b8ff",
      "editor.lineHighlightBackground": "#11192e",
      "editor.lineHighlightBorder": "#ffffff06",
      "editor.selectionBackground": "#26437388",
      "editor.inactiveSelectionBackground": "#1b2e4d66",
      "editor.findMatchBackground": "#9ec0f544",
      "editor.findMatchHighlightBackground": "#9ec0f524",
      "editorStickyScroll.background": "#0c1324",
      "editorStickyScrollHover.background": "#131e36",
      "editorWidget.background": "#101729",
      "editorWidget.border": "#ffffff1a",
      "editorHoverWidget.background": "#101729",
      "editorHoverWidget.border": "#ffffff1f",
      "editorSuggestWidget.background": "#101729",
      "editorSuggestWidget.border": "#ffffff1f",
      "editorSuggestWidget.selectedBackground": "#1d3154",
      "editorIndentGuide.background1": "#ffffff0d",
      "editorIndentGuide.activeBackground1": "#9ec0f533",
      "editorOverviewRuler.border": "#ffffff10",
      "scrollbarSlider.background": "#8595b02e",
      "scrollbarSlider.hoverBackground": "#9ec0f54d",
      "scrollbarSlider.activeBackground": "#9ec0f566",
      "diffEditor.insertedTextBackground": "#5bdba224",
      "diffEditor.insertedLineBackground": "#5bdba214",
      "diffEditor.removedTextBackground": "#f27c7c26",
      "diffEditor.removedLineBackground": "#f27c7c14",
      "diffEditorGutter.insertedLineBackground": "#5bdba240",
      "diffEditorGutter.removedLineBackground": "#f27c7c40",
      "diffEditor.diagonalFill": "#ffffff0a",
      "editorBracketHighlight.foreground1": "#79b8ff",
      "editorBracketHighlight.foreground2": "#c68cff",
      "editorBracketHighlight.foreground3": "#4fd1c5",
      "editorBracketHighlight.foreground4": "#f6ad55",
      "editorBracketHighlight.foreground5": "#6ee7b7",
      "editorBracketHighlight.foreground6": "#f472b6",
    },
  });
}

const TOML_LANGUAGE_CONFIG = {
  comments: {
    lineComment: "#",
  },
  brackets: [
    ["{", "}"],
    ["[", "]"],
  ] as [string, string][],
  autoClosingPairs: [
    { open: "{", close: "}" },
    { open: "[", close: "]" },
    { open: '"', close: '"', notIn: ["string"] },
    { open: "'", close: "'", notIn: ["string"] },
  ],
  surroundingPairs: [
    { open: "{", close: "}" },
    { open: "[", close: "]" },
    { open: '"', close: '"' },
    { open: "'", close: "'" },
  ],
};

function registerTomlLanguage(monaco: MonacoModule): void {
  const alreadyRegistered = monaco.languages
    .getLanguages()
    .some((lang) => lang.id === "toml");

  if (!alreadyRegistered) {
    monaco.languages.register({
      id: "toml",
      extensions: [".toml"],
      aliases: ["TOML", "toml"],
    });
  }

  monaco.languages.setLanguageConfiguration("toml", TOML_LANGUAGE_CONFIG);
  monaco.languages.setMonarchTokensProvider("toml", {
    defaultToken: "",
    tokenPostfix: ".toml",
    tokenizer: {
      root: [
        { include: "@whitespace" },
        [/^\s*\[\[[^\]]+\]\]/, "type"],
        [/^\s*\[[^\]]+\]/, "type"],
        [/([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(\s*)(=)/, ["key", "", "operator"]],
        [/"""/, "string", "@multilineDoubleString"],
        [/'''/, "string", "@multilineSingleString"],
        [/"/, "string", "@doubleString"],
        [/'[^']*'/, "string"],
        [/\b(true|false)\b/, "constant.language"],
        [/\d{4}-\d{2}-\d{2}(?:[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:\d{2})?)?/, "number"],
        [/[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+)/, "number.hex"],
        [/[+-]?(?:\d[\d_]*\.\d[\d_]*(?:[eE][+-]?\d+)?|\d[\d_]*[eE][+-]?\d+|inf|nan)/, "number.float"],
        [/[+-]?\d[\d_]*/, "number"],
        [/[[\]{}]/, "@brackets"],
        [/[=,.]/, "operator"],
      ],
      whitespace: [
        [/[ \t\r\n]+/, ""],
        [/#.*$/, "comment"],
      ],
      doubleString: [
        [/[^\\"]+/, "string"],
        [/\\(?:[btnfr"\\]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/, "string.escape"],
        [/\\./, "invalid"],
        [/"/, "string", "@pop"],
      ],
      multilineDoubleString: [
        [/[^\\"]+/, "string"],
        [/\\(?:[btnfr"\\]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/, "string.escape"],
        [/"""/, "string", "@pop"],
        [/"/, "string"],
      ],
      multilineSingleString: [
        [/[^']+/, "string"],
        [/'''/, "string", "@pop"],
        [/'/, "string"],
      ],
    },
  });
}

const ACCESS_TOML_HOVER_DOCS: Record<string, string> = {
  deny: [
    "**`deny` effect — Deny Overrides Allow**",
    "",
    "In Premier's policy engine, **`deny` always overrides `allow`** at every layer, and **server policies override in-repo `.access.toml`** (`Server > Repo`).",
    "Matched deny bits are subtracted from the accumulated capability bitmask before enforcement across VCS transport, VFS hydration, search, blame, and AI RAG.",
  ].join("\n"),
  allow: [
    "**`allow` effect**",
    "",
    "Grants the listed capability bits to matching principals on matching zones/paths/refs, unless revoked by any matching `deny` rule or a server-level policy (`Server > Repo`).",
  ].join("\n"),
  effect: [
    "**`effect` (`\"allow\"` | `\"deny\"`)**",
    "",
    "Determines whether a `[[rules]]` entry adds or removes capability bits. **Deny always overrides Allow**, and server policy rules override repo policy rules.",
  ].join("\n"),
  traverse: [
    "**`traverse` capability**",
    "",
    "Permits descending through a directory ancestor to reach an allowed descendant **without** exposing sibling filenames, directory listings (`list`), or blob contents (`read`).",
  ].join("\n"),
  list: [
    "**`list` capability**",
    "",
    "Permits viewing tree entries (filenames and object metadata) inside a path or zone. Separate from `traverse` (structural navigation only) and `read` (blob bytes).",
  ].join("\n"),
  read: [
    "**`read` capability**",
    "",
    "Permits receiving file blob bytes over VCS transport, VFS hydration, search, and diff APIs. Distinct from `use` (`use ≠ read` for secrets).",
  ].join("\n"),
  write: [
    "**`write` capability**",
    "",
    "Permits modifying files or pushing changes affecting matching paths/zones.",
  ].join("\n"),
  use: [
    "**`use` capability (`use ≠ read`)**",
    "",
    "Permits invoking an authenticated external service via Premier's host-side egress proxy **without ever exposing raw secret bytes** to the process, disk, `process.env`, or LLM context.",
  ].join("\n"),
  none: [
    "**`none` capability**",
    "",
    "Explicit empty capability bitmask — grants no permissions (`traverse`, `list`, `read`, `write`, `use` all cleared).",
  ].join("\n"),
  rules: [
    "**`[[rules]]` — Access Policy Rule**",
    "",
    "Compiled to a deterministic prefix-trie bitmask evaluated identically across Git transport, VFS, code search, blame, webhooks, CI logs, and AI RAG.",
    "",
    "- **Precedence:** `Server > Repo`, and `deny` overrides `allow`.",
  ].join("\n"),
  zones: [
    "**`[[zones]]` / `[zones.<name>]` — Confidentiality Zone**",
    "",
    "Named grouping of `paths` (and optional `exclude` globs) that defines a path/zone confidentiality boundary for rules and ownership.",
  ].join("\n"),
  agent_profiles: [
    "**`[[agent_profiles]]` — Delegated Agent Ceiling (`H ∩ A`)**",
    "",
    "Defines the maximum authority ceiling for an AI coding agent task.",
    "Effective agent permissions are strictly **`permissions(human) ∩ permissions(agent_task)`** (SPIFFE + delegated OAuth token exchange).",
    "Agents never receive raw secrets; they may only invoke allowed egress endpoints via `allow_secret_use` + `allow_egress_hosts`.",
  ].join("\n"),
  defaults: [
    "**`[defaults]` — Baseline Capabilities**",
    "",
    "Sets baseline capability bitmasks for `public` (anonymous) and `authenticated` principals before `[[rules]]` and server overrides are applied.",
  ].join("\n"),
  quarantine: [
    "**`[quarantine]` — Untrusted Instruction Surfaces**",
    "",
    "Marks repo-resident agent instruction files (such as `AGENTS.md`, `CLAUDE.md`, `.cursorrules`) as untrusted code surfaces that can never silently escalate permissions or egress allow-lists.",
  ].join("\n"),
  instruction_files: [
    "**`instruction_files`**",
    "",
    "Glob/path list of repo-resident AI instruction files flagged under `[quarantine]` to defend against indirect prompt injection under the Lethal Trifecta.",
  ].join("\n"),
  principals: [
    "**`principals`**",
    "",
    "Subjects matched by this rule: `\"*\"`, `\"authenticated\"`, `\"anonymous\"`, `\"@user\"`, `\"user:<id>\"`, `\"group:<name>\"`, `\"team:<name>\"`, `\"agent:<profile>\"`, or `\"spiffe://<trust-domain>/...\"`.",
  ].join("\n"),
  capabilities: [
    "**`capabilities`**",
    "",
    "Subset of `traverse`, `list`, `read`, `write`, `use`, `none`. Remember: `traverse` ≠ `list` ≠ `read`, and `use ≠ read`.",
  ].join("\n"),
  paths: [
    "**`paths`**",
    "",
    "Repository-relative glob patterns matched by the prefix-trie policy compiler. Must not contain `..` traversal segments.",
  ].join("\n"),
  exclude: [
    "**`exclude`**",
    "",
    "Repository-relative glob patterns excluded from the parent zone or rule match. Must not contain `..` traversal segments.",
  ].join("\n"),
  refs: [
    "**`refs`**",
    "",
    "Optional Git ref/branch patterns scoping this rule. Enforced with per-scope OID reachability isolation (never `hideRefs` alone).",
  ].join("\n"),
  spiffe: [
    "**SPIFFE Identity (`spiffe://...`)**",
    "",
    "Cryptographic workload identity bound to delegated agent sessions so effective authority is strictly `permissions(human) ∩ permissions(agent_task)`.",
  ].join("\n"),
};

function registerPremierAccessTomlLanguage(monaco: MonacoModule): void {
  const alreadyRegistered = monaco.languages
    .getLanguages()
    .some((lang) => lang.id === PREMIER_ACCESS_TOML_LANGUAGE);

  if (!alreadyRegistered) {
    monaco.languages.register({
      id: PREMIER_ACCESS_TOML_LANGUAGE,
      extensions: [".access.toml"],
      filenames: [".access.toml", ".access.server.toml"],
      aliases: ["Premier Access Policy", "premier-access-toml"],
    });
  }

  monaco.languages.setLanguageConfiguration(
    PREMIER_ACCESS_TOML_LANGUAGE,
    TOML_LANGUAGE_CONFIG,
  );

  monaco.languages.setMonarchTokensProvider(PREMIER_ACCESS_TOML_LANGUAGE, {
    defaultToken: "",
    tokenPostfix: ".access-toml",
    tokenizer: {
      root: [
        { include: "@whitespace" },

        // Known & custom section headers
        [/^\s*\[\[\s*(?:rules|zones|agent_profiles)\s*\]\]/, "premier.section"],
        [
          /^\s*\[\s*(?:defaults|quarantine|zones(?:\.[A-Za-z0-9_-]+)?)\s*\]/,
          "premier.section",
        ],
        [/^\s*\[\[[^\]]+\]\]/, "premier.section"],
        [/^\s*\[[^\]]+\]/, "premier.section"],

        // Effect assignment highlighted explicitly as allow vs deny
        [
          /\b(effect)(\s*)(=)(\s*)("deny"|'deny')/,
          ["premier.key", "", "operator", "", "premier.effect.deny"],
        ],
        [
          /\b(effect)(\s*)(=)(\s*)("allow"|'allow')/,
          ["premier.key", "", "operator", "", "premier.effect.allow"],
        ],

        // Recognized Premier policy keys
        [
          /\b(version|id|name|description|reason|effect|principals|paths|exclude|capabilities|zones|refs|owners|public|authenticated|instruction_files|allow_paths|deny_paths|allow_secret_use|allow_egress_hosts)(\s*)(=)/,
          ["premier.key", "", "operator"],
        ],

        // Generic TOML keys
        [/([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)(\s*)(=)/, ["key", "", "operator"]],

        // Capability string literals
        [
          /"(?:traverse|list|read|write|use|none)"/,
          "premier.capability",
        ],
        [
          /'(?:traverse|list|read|write|use|none)'/,
          "premier.capability",
        ],

        // Principal string literals
        [
          /"(?:(?:group|user|team|agent):[^"\r\n]*|spiffe:\/\/[^"\r\n]*|@[A-Za-z0-9._-]+|authenticated|anonymous|\*)"/,
          "premier.principal",
        ],
        [
          /'(?:(?:group|user|team|agent):[^'\r\n]*|spiffe:\/\/[^'\r\n]*|@[A-Za-z0-9._-]+|authenticated|anonymous|\*)'/,
          "premier.principal",
        ],

        // Effect literals appearing standalone
        [/"deny"|'deny'/, "premier.effect.deny"],
        [/"allow"|'allow'/, "premier.effect.allow"],

        // Strings
        [/"""/, "string", "@multilineDoubleString"],
        [/'''/, "string", "@multilineSingleString"],
        [/"/, "string", "@doubleString"],
        [/'[^']*'/, "string"],

        // Booleans & numbers
        [/\b(true|false)\b/, "constant.language"],
        [/[+-]?(?:0x[0-9a-fA-F_]+|0o[0-7_]+|0b[01_]+)/, "number.hex"],
        [/[+-]?(?:\d[\d_]*\.\d[\d_]*(?:[eE][+-]?\d+)?|\d[\d_]*[eE][+-]?\d+)/, "number.float"],
        [/[+-]?\d[\d_]*/, "number"],
        [/[[\]{}]/, "@brackets"],
        [/[=,.]/, "operator"],
      ],
      whitespace: [
        [/[ \t\r\n]+/, ""],
        [/#.*$/, "comment"],
      ],
      doubleString: [
        [/[^\\"]+/, "string"],
        [/\\(?:[btnfr"\\]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/, "string.escape"],
        [/\\./, "invalid"],
        [/"/, "string", "@pop"],
      ],
      multilineDoubleString: [
        [/[^\\"]+/, "string"],
        [/\\(?:[btnfr"\\]|u[0-9a-fA-F]{4}|U[0-9a-fA-F]{8})/, "string.escape"],
        [/"""/, "string", "@pop"],
        [/"/, "string"],
      ],
      multilineSingleString: [
        [/[^']+/, "string"],
        [/'''/, "string", "@pop"],
        [/'/, "string"],
      ],
    },
  });

  // Autocomplete provider for Premier `.access.toml`
  monaco.languages.registerCompletionItemProvider(PREMIER_ACCESS_TOML_LANGUAGE, {
    triggerCharacters: ["[", '"', ":", "="],
    provideCompletionItems(model, position) {
      const word = model.getWordUntilPosition(position);
      const linePrefix = model
        .getLineContent(position.lineNumber)
        .slice(0, position.column - 1);

      const range = {
        startLineNumber: position.lineNumber,
        endLineNumber: position.lineNumber,
        startColumn: word.startColumn,
        endColumn: word.endColumn,
      };

      const Kind = monaco.languages.CompletionItemKind;
      const Snippet = monaco.languages.CompletionItemInsertTextRule.InsertAsSnippet;

      const items: import("monaco-editor").languages.CompletionItem[] = [];

      // If starting a line or typing brackets, offer table / array-of-tables snippets
      const trimmedPrefix = linePrefix.trimStart();
      if (trimmedPrefix === "" || trimmedPrefix.startsWith("[")) {
        const bracketStart = linePrefix.indexOf("[");
        const sectionRange =
          bracketStart >= 0
            ? {
                startLineNumber: position.lineNumber,
                endLineNumber: position.lineNumber,
                startColumn: bracketStart + 1,
                endColumn: position.column,
              }
            : range;

        items.push(
          {
            label: "[[rules]]",
            kind: Kind.Snippet,
            insertText: [
              "[[rules]]",
              'id = "${1:rule-id}"',
              'effect = "${2|deny,allow|}"',
              'principals = ["${3:*}"]',
              'paths = ["${4:secret/**}"]',
              'capabilities = ["${5|read,write,list,traverse,use|}"]',
              'reason = "${6:Policy reason}"',
            ].join("\n"),
            insertTextRules: Snippet,
            detail: "Premier access rule block (deny overrides allow)",
            range: sectionRange,
          },
          {
            label: "[[zones]]",
            kind: Kind.Snippet,
            insertText: [
              "[[zones]]",
              'name = "${1:zone-name}"',
              'paths = ["${2:path/**}"]',
              'exclude = ["${3:}"]',
              'description = "${4:Zone description}"',
            ].join("\n"),
            insertTextRules: Snippet,
            detail: "Confidentiality zone array entry",
            range: sectionRange,
          },
          {
            label: "[zones.<name>]",
            kind: Kind.Snippet,
            insertText: [
              "[zones.${1:billing}]",
              'paths = ["${2:billing/**}"]',
              'exclude = []',
              'description = "${3:Zone description}"',
            ].join("\n"),
            insertTextRules: Snippet,
            detail: "Named confidentiality zone table",
            range: sectionRange,
          },
          {
            label: "[[agent_profiles]]",
            kind: Kind.Snippet,
            insertText: [
              "[[agent_profiles]]",
              'name = "${1:code-agent}"',
              'allow_paths = ["${2:src/**}"]',
              'deny_paths = ["${3:secrets/**}"]',
              'capabilities = ["traverse", "list", "read", "write"]',
              'allow_secret_use = ["${4:API_KEY}"]',
              'allow_egress_hosts = ["${5:registry.npmjs.org}"]',
            ].join("\n"),
            insertTextRules: Snippet,
            detail: "Delegated agent capability ceiling (H ∩ A)",
            range: sectionRange,
          },
          {
            label: "[defaults]",
            kind: Kind.Snippet,
            insertText: [
              "[defaults]",
              'public = ["traverse", "list", "read"]',
              'authenticated = ["traverse", "list", "read"]',
            ].join("\n"),
            insertTextRules: Snippet,
            detail: "Default baseline capability bitmasks",
            range: sectionRange,
          },
          {
            label: "[quarantine]",
            kind: Kind.Snippet,
            insertText: [
              "[quarantine]",
              'instruction_files = ["AGENTS.md", "CLAUDE.md", ".cursorrules"]',
            ].join("\n"),
            insertTextRules: Snippet,
            detail: "Quarantine untrusted repo-resident instruction files",
            range: sectionRange,
          },
        );
      }

      // Policy keys
      const policyKeys: Array<[string, string, string]> = [
        ["effect", 'effect = "${1|deny,allow|}"', "Rule effect (deny overrides allow)"],
        ["principals", 'principals = ["${1:*}"]', "Principals matched by this rule"],
        ["paths", 'paths = ["${1:**}"]', "Repository-relative path globs"],
        ["exclude", 'exclude = ["${1:}"]', "Excluded path globs"],
        ["capabilities", 'capabilities = ["${1|traverse,list,read,write,use,none|}"]', "Capability bits"],
        ["zones", 'zones = ["${1:zone}"]', "Named confidentiality zones"],
        ["refs", 'refs = ["${1:refs/heads/main}"]', "Scoped Git refs / branches"],
        ["name", 'name = "${1:name}"', "Zone or agent profile name"],
        ["id", 'id = "${1:rule-id}"', "Unique rule identifier"],
        ["description", 'description = "${1:}"', "Human-readable description"],
        ["reason", 'reason = "${1:}"', "Audit trace explanation"],
        ["instruction_files", 'instruction_files = ["AGENTS.md", "CLAUDE.md"]', "Quarantined instruction files"],
        ["allow_paths", 'allow_paths = ["${1:src/**}"]', "Agent allowed path globs"],
        ["deny_paths", 'deny_paths = ["${1:billing/**}"]', "Agent denied path globs"],
        ["allow_secret_use", 'allow_secret_use = ["${1:SECRET_NAME}"]', "Secrets usable via egress proxy (use ≠ read)"],
        ["allow_egress_hosts", 'allow_egress_hosts = ["${1:api.example.com}"]', "Permitted outbound proxy hosts"],
      ];

      if (!linePrefix.includes("=")) {
        for (const [key, snippet, detail] of policyKeys) {
          items.push({
            label: key,
            kind: Kind.Property,
            insertText: snippet,
            insertTextRules: Snippet,
            detail,
            range,
          });
        }
      }

      // Effects
      for (const eff of ["allow", "deny"]) {
        items.push({
          label: `"${eff}"`,
          kind: Kind.EnumMember,
          insertText: linePrefix.endsWith('"') ? eff : `"${eff}"`,
          detail: eff === "deny" ? "Deny (overrides allow)" : "Allow capability grant",
          range,
        });
      }

      // Capabilities
      const capabilities: Array<[string, string]> = [
        ["traverse", "Descend ancestor dirs without leaking names/hashes"],
        ["list", "List tree entries / filenames"],
        ["read", "Read blob bytes"],
        ["write", "Write / push modifications"],
        ["use", "Invoke secret via egress proxy (use ≠ read)"],
        ["none", "Explicit empty capability set"],
      ];
      for (const [cap, detail] of capabilities) {
        items.push({
          label: `"${cap}"`,
          kind: Kind.Keyword,
          insertText: linePrefix.endsWith('"') ? cap : `"${cap}"`,
          detail,
          range,
        });
      }

      // Principal prefixes & built-ins
      const principals: Array<[string, string]> = [
        ["group:owners", "Directory group principal"],
        ["user:", "Individual user principal prefix"],
        ["team:", "Team principal prefix"],
        ["agent:", "Delegated agent principal prefix"],
        ["spiffe://", "SPIFFE workload identity URI"],
        ["authenticated", "Any authenticated user"],
        ["anonymous", "Unauthenticated public principal"],
        ["*", "Wildcard matching all principals"],
      ];
      for (const [principal, detail] of principals) {
        items.push({
          label: `"${principal}"`,
          kind: Kind.Value,
          insertText: linePrefix.endsWith('"') ? principal : `"${principal}"`,
          detail,
          range,
        });
      }

      return { suggestions: items };
    },
  });

  // Hover provider explaining Premier's access invariants
  monaco.languages.registerHoverProvider(PREMIER_ACCESS_TOML_LANGUAGE, {
    provideHover(model, position) {
      const wordAtPos = model.getWordAtPosition(position);
      if (!wordAtPos) return null;

      const key = wordAtPos.word.toLowerCase();
      const doc = ACCESS_TOML_HOVER_DOCS[key];
      if (!doc) return null;

      return {
        range: {
          startLineNumber: position.lineNumber,
          endLineNumber: position.lineNumber,
          startColumn: wordAtPos.startColumn,
          endColumn: wordAtPos.endColumn,
        },
        contents: [{ value: doc }],
      };
    },
  });
}

/**
 * Maps a repository file path or filename to a registered Monaco language ID.
 */
export function monacoLanguageForPath(path?: string): string {
  if (!path) return "plaintext";

  const normalized = path.replace(/\\/g, "/");
  const base = normalized.slice(normalized.lastIndexOf("/") + 1).toLowerCase();

  // Premier policy files take highest precedence
  if (
    base === ".access.toml" ||
    base === ".access.server.toml" ||
    base === "server-policy.toml" ||
    (base.includes("access") && base.endsWith(".toml"))
  ) {
    return PREMIER_ACCESS_TOML_LANGUAGE;
  }

  if (base === ".env.schema" || base.endsWith(".env.schema") || base === "cargo.lock") {
    return "toml";
  }

  if (base === "dockerfile" || base.startsWith("dockerfile.")) {
    return "dockerfile";
  }

  if (
    base === "caddyfile" ||
    base.startsWith("caddyfile.") ||
    base === "makefile" ||
    base === "gnumakefile"
  ) {
    return "shell";
  }

  if (base === ".env" || base.startsWith(".env.")) {
    return "ini";
  }

  const dotIdx = base.lastIndexOf(".");
  if (dotIdx < 0) return "plaintext";
  const ext = base.slice(dotIdx);

  switch (ext) {
    case ".toml":
      return "toml";
    case ".dockerfile":
      return "dockerfile";
    case ".rs":
      return "rust";
    case ".ts":
    case ".mts":
    case ".cts":
    case ".tsx":
      return "typescript";
    case ".js":
    case ".mjs":
    case ".cjs":
    case ".jsx":
      return "javascript";
    case ".py":
      return "python";
    case ".go":
      return "go";
    case ".json":
    case ".jsonc":
      return "json";
    case ".md":
    case ".mdx":
      return "markdown";
    case ".yml":
    case ".yaml":
      return "yaml";
    case ".sh":
    case ".bash":
    case ".zsh":
      return "shell";
    case ".ps1":
      return "powershell";
    case ".css":
    case ".scss":
    case ".less":
      return "css";
    case ".html":
    case ".htm":
    case ".svg":
      return "html";
    case ".xml":
      return "xml";
    case ".sql":
      return "sql";
    case ".c":
    case ".h":
      return "c";
    case ".cpp":
    case ".cc":
    case ".hpp":
      return "cpp";
    case ".java":
      return "java";
    case ".rb":
      return "ruby";
    case ".php":
      return "php";
    case ".ini":
    case ".conf":
    case ".env":
      return "ini";
    default:
      return "plaintext";
  }
}

const VALID_CAPABILITIES = new Set([
  "traverse",
  "list",
  "read",
  "write",
  "use",
  "none",
]);

const VALID_EFFECTS = new Set(["allow", "deny"]);

const PATH_KEYS = new Set([
  "paths",
  "exclude",
  "allow_paths",
  "deny_paths",
  "instruction_files",
]);

const CAPABILITY_KEYS = new Set(["capabilities", "public", "authenticated"]);

const TOML_TABLE_SEGMENT = `(?:[A-Za-z0-9_-]+|"[^"\\\\]*(?:\\\\.[^"\\\\]*)*"|'[^']*')`;
const VALID_ARRAY_TABLE_RE = new RegExp(
  `^\\[\\[\\s*${TOML_TABLE_SEGMENT}(?:\\s*\\.\\s*${TOML_TABLE_SEGMENT})*\\s*\\]\\]$`,
);
const VALID_TABLE_RE = new RegExp(
  `^\\[\\s*${TOML_TABLE_SEGMENT}(?:\\s*\\.\\s*${TOML_TABLE_SEGMENT})*\\s*\\]$`,
);

interface LineScanResult {
  code: string;
  inTripleDouble: boolean;
  inTripleSingle: boolean;
  unclosedQuote: '"' | "'" | null;
  unclosedQuoteCol: number;
}

/**
 * Single-pass TOML line scanner that tracks multiline triple-quoted strings,
 * single-line basic/literal strings, and strips comments outside strings.
 */
function scanTomlLine(
  rawLine: string,
  startTripleDouble: boolean,
  startTripleSingle: boolean,
): LineScanResult {
  let inTripleDouble = startTripleDouble;
  let inTripleSingle = startTripleSingle;
  let inDouble = false;
  let inSingle = false;
  let escaped = false;
  let quoteStartCol = 1;
  let codeEnd = rawLine.length;

  for (let i = 0; i < rawLine.length; i++) {
    const ch = rawLine[i];

    if (inTripleDouble) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (rawLine.startsWith('"""', i)) {
        inTripleDouble = false;
        i += 2;
      }
      continue;
    }

    if (inTripleSingle) {
      if (rawLine.startsWith("'''", i)) {
        inTripleSingle = false;
        i += 2;
      }
      continue;
    }

    if (inDouble) {
      if (escaped) {
        escaped = false;
      } else if (ch === "\\") {
        escaped = true;
      } else if (ch === '"') {
        inDouble = false;
      }
      continue;
    }

    if (inSingle) {
      if (ch === "'") {
        inSingle = false;
      }
      continue;
    }

    if (ch === "#") {
      codeEnd = i;
      break;
    }

    if (rawLine.startsWith('"""', i)) {
      inTripleDouble = true;
      i += 2;
      continue;
    }

    if (rawLine.startsWith("'''", i)) {
      inTripleSingle = true;
      i += 2;
      continue;
    }

    if (ch === '"') {
      inDouble = true;
      quoteStartCol = i + 1;
    } else if (ch === "'") {
      inSingle = true;
      quoteStartCol = i + 1;
    }
  }

  return {
    code: rawLine.slice(0, codeEnd),
    inTripleDouble,
    inTripleSingle,
    unclosedQuote: inDouble ? '"' : inSingle ? "'" : null,
    unclosedQuoteCol: quoteStartCol,
  };
}

function hasPathTraversalSegment(value: string): boolean {
  const normalized = value.replace(/\\/g, "/");
  return normalized.split("/").some((segment) => segment === "..");
}

/**
 * Client-side syntax & semantic validator for Premier `.access.toml` policies.
 * Also extracts line/column diagnostics from `serverError` when present.
 */
export function validateAccessToml(
  text: string,
  serverError?: string | null,
): MonacoMarkerInput[] {
  const markers: MonacoMarkerInput[] = [];
  const lines = text.split(/\r?\n/);

  let inTripleDouble = false;
  let inTripleSingle = false;
  let bracketDepth = 0;
  let bracketOpenLine = 1;
  let bracketOpenCol = 1;
  let activeArrayKey: string | null = null;
  let currentSection = "";
  const seenRuleIds = new Map<string, number>();

  for (let idx = 0; idx < lines.length; idx++) {
    const lineNum = idx + 1;
    const rawLine = lines[idx];

    const startedInMultiline = inTripleDouble || inTripleSingle;
    const scan = scanTomlLine(rawLine, inTripleDouble, inTripleSingle);
    inTripleDouble = scan.inTripleDouble;
    inTripleSingle = scan.inTripleSingle;

    if (startedInMultiline) {
      continue;
    }

    if (scan.unclosedQuote) {
      markers.push({
        startLineNumber: lineNum,
        startColumn: scan.unclosedQuoteCol,
        endLineNumber: lineNum,
        endColumn: rawLine.length + 1,
        message:
          scan.unclosedQuote === '"'
            ? "Unclosed double-quoted string."
            : "Unclosed single-quoted string.",
        severity: "error",
      });
      continue;
    }

    // If a multiline string started on this line and didn't close on this line, continue scanning lines.
    if (inTripleDouble || inTripleSingle) {
      continue;
    }

    const code = scan.code;
    const trimmed = code.trim();
    if (!trimmed) continue;

    // Section headers (only when not inside a multiline array)
    if (bracketDepth === 0 && trimmed.startsWith("[")) {
      const isArrayTable = trimmed.startsWith("[[");
      const validArrayTable = VALID_ARRAY_TABLE_RE.test(trimmed);
      const validTable = VALID_TABLE_RE.test(trimmed);

      if ((isArrayTable && !validArrayTable) || (!isArrayTable && !validTable)) {
        const startCol = rawLine.indexOf("[") + 1;
        markers.push({
          startLineNumber: lineNum,
          startColumn: startCol,
          endLineNumber: lineNum,
          endColumn: rawLine.trimEnd().length + 1,
          message: isArrayTable
            ? "Malformed array-of-tables header (expected `[[section]]`)."
            : "Malformed table section header (expected `[section]`).",
          severity: "error",
        });
      } else {
        currentSection = trimmed.replace(/^\[+|\]+$/g, "").trim();
      }
      activeArrayKey = null;
      continue;
    }

    // Check bracket balance (ignoring brackets inside strings)
    let lineKey: string | null = null;
    let valueStartOffset = 0;
    if (bracketDepth === 0) {
      const kvMatch = code.match(/^\s*([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\s*=\s*(.*)$/);
      if (kvMatch) {
        lineKey = kvMatch[1];
        const eqIdx = code.indexOf("=");
        valueStartOffset = eqIdx >= 0 ? eqIdx + 1 : 0;
      }
    }

    let strDouble = false;
    let strSingle = false;
    let strTripleDouble = false;
    let strTripleSingle = false;
    let strEsc = false;
    for (let i = 0; i < code.length; i++) {
      const ch = code[i];
      if (strTripleDouble) {
        if (strEsc) strEsc = false;
        else if (ch === "\\") strEsc = true;
        else if (code.startsWith('"""', i)) {
          strTripleDouble = false;
          i += 2;
        }
        continue;
      }
      if (strTripleSingle) {
        if (code.startsWith("'''", i)) {
          strTripleSingle = false;
          i += 2;
        }
        continue;
      }
      if (strDouble) {
        if (strEsc) strEsc = false;
        else if (ch === "\\") strEsc = true;
        else if (ch === '"') strDouble = false;
        continue;
      }
      if (strSingle) {
        if (ch === "'") strSingle = false;
        continue;
      }
      if (code.startsWith('"""', i)) {
        strTripleDouble = true;
        i += 2;
      } else if (code.startsWith("'''", i)) {
        strTripleSingle = true;
        i += 2;
      } else if (ch === '"') {
        strDouble = true;
      } else if (ch === "'") {
        strSingle = true;
      } else if (ch === "[") {
        if (bracketDepth === 0) {
          bracketOpenLine = lineNum;
          bracketOpenCol = i + 1;
          activeArrayKey = lineKey;
        }
        bracketDepth++;
      } else if (ch === "]") {
        bracketDepth--;
        if (bracketDepth < 0) {
          markers.push({
            startLineNumber: lineNum,
            startColumn: i + 1,
            endLineNumber: lineNum,
            endColumn: i + 2,
            message: "Unexpected closing bracket `]`.",
            severity: "error",
          });
          bracketDepth = 0;
        } else if (bracketDepth === 0) {
          // Validate inline or completed array items on this line before clearing activeArrayKey
          validateArrayLineLiterals(
            code,
            valueStartOffset,
            lineNum,
            activeArrayKey ?? lineKey,
            currentSection,
            markers,
          );
          activeArrayKey = null;
        }
      }
    }

    // If still inside a multi-line array, validate literals on this line
    if (bracketDepth > 0) {
      validateArrayLineLiterals(
        code,
        valueStartOffset,
        lineNum,
        activeArrayKey ?? lineKey,
        currentSection,
        markers,
      );
      continue;
    }

    // Single-line key = value semantic checks
    const kvMatch = code.match(/^\s*([A-Za-z0-9_-]+(?:\.[A-Za-z0-9_-]+)*)\s*=\s*(.+)$/);
    if (!kvMatch) continue;
    const key = kvMatch[1];
    const rhs = kvMatch[2].trim();

    if (key === "effect") {
      const m = rhs.match(/^["']([^"']*)["']$/);
      const val = m ? m[1] : null;
      if (!val || !VALID_EFFECTS.has(val)) {
        const startCol = rawLine.indexOf("=") + 2;
        markers.push({
          startLineNumber: lineNum,
          startColumn: Math.max(1, startCol),
          endLineNumber: lineNum,
          endColumn: rawLine.trimEnd().length + 1,
          message: `Invalid effect "${val ?? rhs}". Must be "allow" or "deny" (deny overrides allow).`,
          severity: "error",
        });
      }
    }

    if (key === "id" && currentSection === "rules") {
      const m = rhs.match(/^["']([^"']+)["']$/);
      if (m) {
        const ruleId = m[1];
        const prevLine = seenRuleIds.get(ruleId);
        if (prevLine !== undefined) {
          const idIdx = rawLine.indexOf(ruleId);
          markers.push({
            startLineNumber: lineNum,
            startColumn: idIdx >= 0 ? idIdx + 1 : 1,
            endLineNumber: lineNum,
            endColumn: idIdx >= 0 ? idIdx + 1 + ruleId.length : rawLine.length + 1,
            message: `Duplicate rule id "${ruleId}" (first declared on line ${prevLine}).`,
            severity: "warning",
          });
        } else {
          seenRuleIds.set(ruleId, lineNum);
        }
      }
    }

    // Also catch non-array string value on path keys
    if (PATH_KEYS.has(key) && !rhs.startsWith("[")) {
      const m = rhs.match(/^["']([^"']+)["']$/);
      if (m && hasPathTraversalSegment(m[1])) {
        const pIdx = rawLine.indexOf(m[1]);
        markers.push({
          startLineNumber: lineNum,
          startColumn: pIdx >= 0 ? pIdx + 1 : 1,
          endLineNumber: lineNum,
          endColumn: pIdx >= 0 ? pIdx + 1 + m[1].length : rawLine.length + 1,
          message: `Path "${m[1]}" contains disallowed ".." traversal segment.`,
          severity: "error",
        });
      }
    }
  }

  if (inTripleDouble || inTripleSingle) {
    const lastLine = Math.max(1, lines.length);
    markers.push({
      startLineNumber: lastLine,
      startColumn: 1,
      endLineNumber: lastLine,
      endColumn: (lines[lastLine - 1]?.length ?? 0) + 1,
      message: "Unclosed multi-line string literal.",
      severity: "error",
    });
  }

  if (bracketDepth > 0) {
    markers.push({
      startLineNumber: bracketOpenLine,
      startColumn: bracketOpenCol,
      endLineNumber: bracketOpenLine,
      endColumn: bracketOpenCol + 1,
      message: "Unclosed array bracket `[`.",
      severity: "error",
    });
  }

  // Parse server error (including line/column when reported by the TOML/policy parser)
  if (serverError && serverError.trim()) {
    const trimmedErr = serverError.trim();
    const maxLine = Math.max(1, lines.length);
    let errLine = 1;
    let errCol = 1;

    const lineColMatch =
      trimmedErr.match(/\bline\s+(\d+)(?:(?:,\s*|\s+)(?:col(?:umn)?)\s+(\d+)|:(\d+))?/i) ??
      trimmedErr.match(/:(\d+):(\d+)\b/);

    if (lineColMatch) {
      errLine = Math.min(maxLine, Math.max(1, Number.parseInt(lineColMatch[1], 10) || 1));
      const colStr = lineColMatch[2] ?? lineColMatch[3];
      if (colStr) {
        errCol = Math.max(1, Number.parseInt(colStr, 10) || 1);
      }
    }

    const lineLen = (lines[errLine - 1]?.length ?? 0) + 1;
    markers.push({
      startLineNumber: errLine,
      startColumn: Math.min(errCol, lineLen),
      endLineNumber: errLine,
      endColumn: Math.max(lineLen, errCol + 1),
      message: trimmedErr,
      severity: "error",
    });
  }

  return markers;
}

function validateArrayLineLiterals(
  code: string,
  startOffset: number,
  lineNum: number,
  key: string | null,
  section: string,
  markers: MonacoMarkerInput[],
): void {
  if (!key) return;

  const isCapKey =
    key === "capabilities" ||
    key === "defaults.public" ||
    key === "defaults.authenticated" ||
    (section === "defaults" && CAPABILITY_KEYS.has(key));
  const isPathKey = PATH_KEYS.has(key);

  if (!isCapKey && !isPathKey) return;

  const slice = startOffset > 0 ? code.slice(startOffset) : code;
  const literalRe = /"([^"\\]*(?:\\.[^"\\]*)*)"|'([^']*)'/g;
  let match: RegExpExecArray | null;
  while ((match = literalRe.exec(slice)) !== null) {
    const val = match[1] ?? match[2] ?? "";
    const startCol = startOffset + match.index + 1;
    const endCol = startOffset + match.index + match[0].length + 1;

    if (isCapKey && !VALID_CAPABILITIES.has(val)) {
      markers.push({
        startLineNumber: lineNum,
        startColumn: startCol,
        endLineNumber: lineNum,
        endColumn: endCol,
        message: `Unknown capability "${val}". Valid capabilities: traverse, list, read, write, use, none.`,
        severity: "error",
      });
    }

    if (isPathKey && hasPathTraversalSegment(val)) {
      markers.push({
        startLineNumber: lineNum,
        startColumn: startCol,
        endLineNumber: lineNum,
        endColumn: endCol,
        message: `Path "${val}" contains disallowed ".." traversal segment.`,
        severity: "error",
      });
    }
  }
}

const HUNK_HEADER_RE = /^@@\s+-(\d+)(?:,(\d+))?\s+\+(\d+)(?:,(\d+))?\s+@@(.*)$/;

function isUnifiedDiffPreamble(line: string): boolean {
  return (
    line.startsWith("diff --git ") ||
    line.startsWith("index ") ||
    line.startsWith("--- ") ||
    line.startsWith("+++ ") ||
    line.startsWith("new file mode ") ||
    line.startsWith("deleted file mode ") ||
    line.startsWith("old mode ") ||
    line.startsWith("new mode ") ||
    line.startsWith("similarity index ") ||
    line.startsWith("dissimilarity index ") ||
    line.startsWith("rename from ") ||
    line.startsWith("rename to ") ||
    line.startsWith("copy from ") ||
    line.startsWith("copy to ") ||
    line.startsWith("Binary files ")
  );
}

/**
 * Reconstructs aligned original and modified buffers from a unified diff patch
 * so Monaco's DiffEditor can render rich syntax-highlighted diffs with real file
 * line numbers preserved in `originalLineMap` / `modifiedLineMap` (`0` for synthetic
 * multi-hunk separator lines).
 */
export function unifiedPatchToSides(patch: string): UnifiedPatchSides {
  if (!patch) {
    return {
      original: "",
      modified: "",
      hasChanges: false,
      originalLineMap: [],
      modifiedLineMap: [],
    };
  }

  const rawLines = patch.split(/\r?\n/);
  // Trim only a single trailing empty element produced by a final newline
  if (patch.endsWith("\n") && rawLines.length > 0 && rawLines[rawLines.length - 1] === "") {
    rawLines.pop();
  }

  const originalLines: string[] = [];
  const modifiedLines: string[] = [];
  const originalLineMap: number[] = [];
  const modifiedLineMap: number[] = [];

  let inHunk = false;
  let hunkCount = 0;
  let hasChanges = false;
  let oldLine = 1;
  let newLine = 1;
  let oldRemaining = 0;
  let newRemaining = 0;

  for (const line of rawLines) {
    // Skip `\ No newline at end of file` (and any backslash diff meta note) without shifting counts
    if (line.startsWith("\\")) {
      continue;
    }

    // A hunk header `@@ -a,b +c,d @@` never starts with `+`, `-`, or ` `, so it cannot collide with hunk body lines
    const hunkMatch = line.match(HUNK_HEADER_RE);
    if (hunkMatch) {
      oldLine = Number.parseInt(hunkMatch[1], 10);
      oldRemaining = hunkMatch[2] !== undefined ? Number.parseInt(hunkMatch[2], 10) : 1;
      newLine = Number.parseInt(hunkMatch[3], 10);
      newRemaining = hunkMatch[4] !== undefined ? Number.parseInt(hunkMatch[4], 10) : 1;

      if (hunkCount > 0) {
        const separator = `// ... (hunk ${line.trim()})`;
        originalLines.push(separator);
        modifiedLines.push(separator);
        originalLineMap.push(0);
        modifiedLineMap.push(0);
      }

      hunkCount++;
      inHunk = true;
      continue;
    }

    // Only skip unified diff preamble headers OUTSIDE active hunk body counts,
    // so deleted `-- ...` (`--- ...`) or added `++ ...` (`+++ ...`) lines inside a hunk
    // are NEVER mistakenly dropped!
    if (!inHunk) {
      continue;
    }

    if (oldRemaining <= 0 && newRemaining <= 0 && isUnifiedDiffPreamble(line)) {
      inHunk = false;
      continue;
    }

    if (line.startsWith("-")) {
      originalLines.push(line.slice(1));
      originalLineMap.push(oldLine++);
      if (oldRemaining > 0) oldRemaining--;
      hasChanges = true;
    } else if (line.startsWith("+")) {
      modifiedLines.push(line.slice(1));
      modifiedLineMap.push(newLine++);
      if (newRemaining > 0) newRemaining--;
      hasChanges = true;
    } else if (line.startsWith(" ")) {
      const content = line.slice(1);
      originalLines.push(content);
      modifiedLines.push(content);
      originalLineMap.push(oldLine++);
      modifiedLineMap.push(newLine++);
      if (oldRemaining > 0) oldRemaining--;
      if (newRemaining > 0) newRemaining--;
    } else if (line === "" && (oldRemaining > 0 || newRemaining > 0)) {
      // Some diff generators omit the leading space on empty context lines
      originalLines.push("");
      modifiedLines.push("");
      originalLineMap.push(oldLine++);
      modifiedLineMap.push(newLine++);
      if (oldRemaining > 0) oldRemaining--;
      if (newRemaining > 0) newRemaining--;
    }
  }

  return {
    original: originalLines.join("\n"),
    modified: modifiedLines.join("\n"),
    hasChanges,
    originalLineMap,
    modifiedLineMap,
  };
}
