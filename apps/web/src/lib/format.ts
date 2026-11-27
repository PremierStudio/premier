/** "1 file", "2 files". Pass `many` for irregular plurals ("branch", "branches"). */
export const plural = (n: number, one: string, many = `${one}s`): string =>
  `${n} ${n === 1 ? one : many}`;

function parseTime(value: string): Date | null {
  // Git's `%ci` ("2026-11-22 02:11:00 -0600") is not ISO; make it so before parsing.
  const iso = value.replace(/^(\d{4}-\d\d-\d\d) (\d\d:\d\d:\d\d) ([+-]\d\d)(\d\d)$/, "$1T$2$3:$4");
  const d = new Date(iso);
  return Number.isNaN(d.getTime()) ? null : d;
}

/** The one timestamp format of the app: viewer-local "Nov 22, 02:11" (year added when not this year). */
export function formatTime(value: string | null | undefined): string {
  if (!value) return "never";
  const d = parseTime(value);
  if (!d) return value;
  return d.toLocaleString("en-US", {
    month: "short",
    day: "numeric",
    year: d.getFullYear() === new Date().getFullYear() ? undefined : "numeric",
    hour: "2-digit",
    minute: "2-digit",
    hourCycle: "h23",
  });
}

/** Full ISO value for a `title` attribute; undefined when there is no parseable time. */
export function isoTime(value: string | null | undefined): string | undefined {
  return (value ? parseTime(value) : null)?.toISOString();
}
