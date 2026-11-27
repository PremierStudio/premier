import { useEffect, useState } from "react";

export type ClientOS = "macos" | "windows" | "linux";

export type ShortcutModifier = "⌘" | "Ctrl";

export interface FormattedShortcut {
  modifier: ShortcutModifier;
  key: string;
}

interface NavigatorWithUserAgentData extends Navigator {
  userAgentData?: {
    platform?: string;
  };
}

function classifyPlatformString(value: string | undefined | null): ClientOS | null {
  if (!value) return null;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return null;

  if (/(?:^|[^a-z])(?:mac|darwin|iphone|ipad|ipod)/.test(normalized)) {
    return "macos";
  }
  if (/(?:^|[^a-z])win/.test(normalized)) {
    return "windows";
  }
  if (/(?:^|[^a-z])(?:linux|x11|cros)/.test(normalized)) {
    return "linux";
  }
  return null;
}

export function detectClientOS(): ClientOS {
  if (typeof navigator === "undefined") {
    return "linux";
  }

  const nav = navigator as NavigatorWithUserAgentData;
  const candidates: Array<string | undefined> = [
    nav.userAgentData?.platform,
    navigator.platform,
    navigator.userAgent,
  ];

  for (const candidate of candidates) {
    const detected = classifyPlatformString(candidate);
    if (detected) {
      return detected;
    }
  }

  return "linux";
}

export function useClientOS(): ClientOS {
  const [os, setOS] = useState<ClientOS>(() => detectClientOS());

  useEffect(() => {
    const detected = detectClientOS();
    setOS((current) => (current === detected ? current : detected));
  }, []);

  return os;
}

export function isMac(os: ClientOS = detectClientOS()): boolean {
  return os === "macos";
}

export function getPrimaryModifier(os: ClientOS = detectClientOS()): ShortcutModifier {
  return isMac(os) ? "⌘" : "Ctrl";
}

export function getShiftSymbol(os: ClientOS = detectClientOS()): string {
  return isMac(os) ? "⇧" : "Shift";
}

export function getAltSymbol(os: ClientOS = detectClientOS()): string {
  return isMac(os) ? "⌥" : "Alt";
}

export function getOSLabel(os: ClientOS): string {
  switch (os) {
    case "macos":
      return "macOS";
    case "windows":
      return "Windows";
    case "linux":
      return "Linux";
  }
}

export function formatShortcut(key: string, os: ClientOS): FormattedShortcut {
  const trimmed = key.trim();
  const normalizedKey = trimmed.length === 1 ? trimmed.toUpperCase() : trimmed;
  return {
    modifier: getPrimaryModifier(os),
    key: normalizedKey,
  };
}

export function formatShortcutParts(
  key: string,
  os: ClientOS,
  opts?: { shift?: boolean; alt?: boolean },
): string[] {
  const parts: string[] = [getPrimaryModifier(os)];
  if (opts?.alt) parts.push(getAltSymbol(os));
  if (opts?.shift) parts.push(getShiftSymbol(os));
  const trimmed = key.trim();
  parts.push(trimmed.length === 1 ? trimmed.toUpperCase() : trimmed);
  return parts;
}

export function formatShortcutLabel(key: string, os: ClientOS): string {
  const { modifier, key: formattedKey } = formatShortcut(key, os);
  return isMac(os) ? `${modifier}${formattedKey}` : `${modifier}+${formattedKey}`;
}

export function hasPrimaryModifier(
  event: Pick<KeyboardEvent, "metaKey" | "ctrlKey">,
  os: ClientOS = detectClientOS(),
): boolean {
  return isMac(os) ? event.metaKey : event.ctrlKey;
}

/** True when a keyboard event originates from an editable control (input/textarea/select/contentEditable/Monaco). */
export function isEditableEventTarget(event: KeyboardEvent): boolean {
  const target = event.target as HTMLElement | null;
  if (!target) return false;
  const tag = target.tagName;
  if (tag === "INPUT" || tag === "TEXTAREA" || tag === "SELECT") {
    return true;
  }
  if (target.isContentEditable) {
    return true;
  }
  // Monaco 0.57+ uses native EditContext (<div class="native-edit-context">) in Chromium,
  // which is neither a textarea nor contentEditable. Guard all keystrokes inside Monaco so
  // global 1-7 / g-chord / j-k shortcuts never hijack typing or editor navigation.
  if (typeof target.closest === "function" && target.closest(".monaco-editor")) {
    return true;
  }
  return false;
}
