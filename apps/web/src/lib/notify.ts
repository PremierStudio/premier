import type { PendingApproval } from "../api";

const KEY = "sf.desktop-notifications";

/** True only when the user turned the toggle on AND the browser permission is still granted. */
export function desktopNotificationsOn(): boolean {
  try {
    return (
      "Notification" in window &&
      Notification.permission === "granted" &&
      localStorage.getItem(KEY) === "1"
    );
  } catch {
    return false;
  }
}

/** Turns the toggle on (asking the browser for permission) or off. Resolves to the new state. */
export async function setDesktopNotifications(on: boolean): Promise<boolean> {
  if (on) {
    if (!("Notification" in window)) throw new Error("This browser doesn't support notifications.");
    if ((await Notification.requestPermission()) !== "granted") {
      throw new Error(
        "Notifications are blocked for this site. Allow them in your browser's site settings, then try again.",
      );
    }
  }
  try {
    if (on) localStorage.setItem(KEY, "1");
    else localStorage.removeItem(KEY);
  } catch {
    if (on) throw new Error("Couldn't save the setting: browser storage is unavailable.");
  }
  return on;
}

/** Shows a notification for a new pending approval when the tab isn't focused. */
export function notifyPendingApproval(ap: PendingApproval): void {
  if (document.hasFocus() || !desktopNotificationsOn()) return;
  try {
    const n = new Notification("Premier: approval needed", {
      body:
        ap.intent_summary ||
        `${ap.principal}${ap.agent_profile ? ` ∩ ${ap.agent_profile}` : ""} wants ${ap.var_name} for ${ap.method} ${ap.host}`,
      tag: ap.id,
    });
    n.onclick = () => window.focus();
  } catch {
    // Some browsers only allow notifications from a service worker; nothing to fall back to.
  }
}
