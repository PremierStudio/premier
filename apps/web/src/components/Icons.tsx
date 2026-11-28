import { useId, type SVGProps } from "react";
import { useClientOS, type ClientOS } from "../lib/platform";

export type IconProps = SVGProps<SVGSVGElement>;

const DEFAULT_ICON_SIZE = "h-[18px] w-[18px]";
const DEFAULT_MARK_SIZE = "h-7 w-7";

function resolveIconClass(className?: string, defaultSize = DEFAULT_ICON_SIZE): string {
  if (!className) {
    return `${defaultSize} shrink-0`;
  }
  const hasExplicitSize = /\b(?:h-|w-|size-)/.test(className);
  const hasExplicitShrink = /\bshrink-/.test(className);
  return [hasExplicitSize ? "" : defaultSize, hasExplicitShrink ? "" : "shrink-0", className]
    .filter(Boolean)
    .join(" ");
}

/** Bespoke Premier emblem: dual split-plane obsidian-glass prisms converging over a canonical core. */
export function PremierMark({ className, ...props }: IconProps) {
  const uid = useId();
  const topGradId = `pr-mark-top-${uid}`;
  const botGradId = `pr-mark-bot-${uid}`;

  return (
    <svg
      viewBox="0 0 28 28"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className, DEFAULT_MARK_SIZE)}
      {...props}
    >
      <defs>
        <linearGradient id={topGradId} x1="4" y1="3.5" x2="24" y2="16" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#eef3ff" />
          <stop offset="52%" stopColor="#9ab0ff" />
          <stop offset="100%" stopColor="#6179f6" />
        </linearGradient>
        <linearGradient id={botGradId} x1="4" y1="15" x2="24" y2="25" gradientUnits="userSpaceOnUse">
          <stop offset="0%" stopColor="#77e0f0" stopOpacity="0.95" />
          <stop offset="100%" stopColor="#4f60da" stopOpacity="0.78" />
        </linearGradient>
      </defs>
      <path d="M4.5 11.2L14 4.4L23.5 11.2L14 16.2L4.5 11.2Z" fill={`url(#${topGradId})`} />
      <path d="M14 7.6L17.4 10.2L14 12.6L10.6 10.2L14 7.6Z" fill="#ffffff" fillOpacity="0.18" />
      <path d="M4.5 16.8L14 21.5L23.5 16.8L14 24L4.5 16.8Z" fill={`url(#${botGradId})`} />
      <path
        d="M4.5 11.2L14 16.2L23.5 11.2"
        stroke="#ffffff"
        strokeOpacity="0.56"
        strokeWidth="1.05"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Worktable grid: two presence panes on the left, a judgment rail plane on the right. */
export function IconWorktable({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect
        x="3"
        y="4"
        width="10"
        height="7"
        rx="2"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <rect
        x="3"
        y="13.75"
        width="10"
        height="6.25"
        rx="2"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeOpacity="0.72"
      />
      <rect
        x="15.5"
        y="4"
        width="5.5"
        height="16"
        rx="2"
        fill="currentColor"
        fillOpacity="0.2"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M17.6 8.5H18.9M17.6 12H18.9M17.6 15.5H18.9"
        stroke="currentColor"
        strokeOpacity="0.6"
        strokeWidth="1.65"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Layered repository code brackets with obsidian-glass interior plane. */
export function IconCode({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M8.5 7.25L3.5 12L8.5 16.75H15.5L20.5 12L15.5 7.25H8.5Z"
        fill="currentColor"
        fillOpacity="0.12"
      />
      <path
        d="M8.5 7.25L3.5 12L8.5 16.75M15.5 7.25L20.5 12L15.5 16.75"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M13.6 5.5L10.4 18.5"
        stroke="currentColor"
        strokeOpacity="0.68"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Commit rail & Change-Id rounds. */
export function IconChanges({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="7"
        cy="6.25"
        r="2.65"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <circle
        cx="17"
        cy="17.75"
        r="2.65"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M7 8.9V13.75C7 15.96 8.79 17.75 11 17.75H14.35"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M13 6.25H19"
        stroke="currentColor"
        strokeOpacity="0.58"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
      <path
        d="M14.75 10.75H19"
        stroke="currentColor"
        strokeOpacity="0.38"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Private branch projection fork. */
export function IconBranches({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="6.75"
        cy="5.75"
        r="2.5"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <circle
        cx="6.75"
        cy="18.25"
        r="2.5"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <circle
        cx="17.25"
        cy="9.75"
        r="2.5"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M6.75 8.25V15.75M6.75 15.75C6.75 12.1 9.65 9.75 14.75 9.75"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Hexagonal egress capability cage. */
export function IconCage({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M12 2.75L20 7.35V16.65L12 21.25L4 16.65V7.35L12 2.75Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path
        d="M12 2.75V9.25M20 16.65L14.38 13.38M4 16.65L9.62 13.38"
        stroke="currentColor"
        strokeOpacity="0.45"
        strokeWidth="1.65"
        strokeLinecap="round"
      />
      <circle
        cx="12"
        cy="12"
        r="2.75"
        fill="currentColor"
        fillOpacity="0.2"
        stroke="currentColor"
        strokeWidth="1.85"
      />
    </svg>
  );
}

/** Capability vault (use != read). */
export function IconVault({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect
        x="3.25"
        y="4.75"
        width="17.5"
        height="14.5"
        rx="3.25"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <circle
        cx="9.75"
        cy="12"
        r="2.6"
        fill="currentColor"
        fillOpacity="0.16"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M12.35 12H17.25M15.65 12V14.4"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Layered policy planes (Server > Repo). */
export function IconPolicy({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M12 3.25L20.5 8L12 12.75L3.5 8L12 3.25Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path
        d="M3.5 12.25L12 17L20.5 12.25"
        stroke="currentColor"
        strokeOpacity="0.72"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M3.5 16.25L12 21L20.5 16.25"
        stroke="currentColor"
        strokeOpacity="0.42"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Six-tooth settings gear with dual-tone hub. */
export function IconGear({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="12"
        cy="12"
        r="6.1"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M12 2.75V5.9M12 18.1V21.25M3.99 7.38L6.72 8.95M17.28 15.05L20.01 16.63M3.99 16.63L6.72 15.05M17.28 8.95L20.01 7.38"
        stroke="currentColor"
        strokeWidth="2.6"
        strokeLinecap="round"
      />
      <circle cx="12" cy="12" r="2.2" stroke="currentColor" strokeWidth="1.85" />
    </svg>
  );
}

/** Signed-in account glyph: head over shoulder plane. */
export function IconUser({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="12"
        cy="8.25"
        r="3.75"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M4.75 19.75C5.6 16.5 8.5 14.75 12 14.75C15.5 14.75 18.4 16.5 19.25 19.75"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Geometric Venn intersection glyph (human ∩ agent) — zero cliché sparkles. */
export function IconIntersection({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="9"
        cy="12"
        r="5.5"
        fill="currentColor"
        fillOpacity="0.1"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <circle
        cx="15"
        cy="12"
        r="5.5"
        fill="currentColor"
        fillOpacity="0.1"
        stroke="currentColor"
        strokeOpacity="0.72"
        strokeWidth="1.85"
      />
      <path
        d="M12 7.39A5.5 5.5 0 0 1 12 16.61A5.5 5.5 0 0 1 12 7.39Z"
        fill="currentColor"
        fillOpacity="0.2"
      />
    </svg>
  );
}

/** Precision optical lens aperture. */
export function IconLens({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="12"
        cy="12"
        r="8.25"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <circle cx="12" cy="12" r="4.5" stroke="currentColor" strokeOpacity="0.4" strokeWidth="1.4" />
      <circle cx="12" cy="12" r="2.1" fill="currentColor" />
    </svg>
  );
}

/** Closed directory node (solid dual-tone when readable, dashed outline when traverse-only). */
export function IconFolderNode({
  traverseOnly = false,
  className,
  ...props
}: IconProps & { traverseOnly?: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M3 6.75C3 5.51 4.01 4.5 5.25 4.5H9.1C9.68 4.5 10.23 4.74 10.62 5.17L11.88 6.55H18.75C19.99 6.55 21 7.56 21 8.8V17.25C21 18.49 19.99 19.5 18.75 19.5H5.25C4.01 19.5 3 18.49 3 17.25V6.75Z"
        fill="currentColor"
        fillOpacity={traverseOnly ? "0.05" : "0.12"}
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
        strokeDasharray={traverseOnly ? "3.2 2.4" : undefined}
      />
    </svg>
  );
}

/** Open directory node for expanded tree folders. */
export function IconFolderOpen({
  traverseOnly = false,
  className,
  ...props
}: IconProps & { traverseOnly?: boolean }) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M3.25 7C3.25 5.76 4.26 4.75 5.5 4.75H9.2L11 6.75H18C19.1 6.75 20 7.65 20 8.75V10.25H6.2L3.25 17.5V7Z"
        stroke="currentColor"
        strokeOpacity="0.65"
        strokeWidth="1.75"
        strokeLinejoin="round"
        strokeDasharray={traverseOnly ? "3 2.2" : undefined}
      />
      <path
        d="M5.6 10.25H20.75L18.6 18.25C18.36 19.05 17.62 19.5 16.8 19.5H4.9C3.95 19.5 3.35 18.6 3.65 17.7L5.6 10.25Z"
        fill="currentColor"
        fillOpacity={traverseOnly ? "0.06" : "0.16"}
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
        strokeDasharray={traverseOnly ? "3 2.2" : undefined}
      />
    </svg>
  );
}

/** Architectural file node with folded corner plane. */
export function IconFileNode({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M5.5 4.25C5.5 3.42 6.17 2.75 7 2.75H13.6L18.5 7.65V19.75C18.5 20.58 17.83 21.25 17 21.25H7C6.17 21.25 5.5 20.58 5.5 19.75V4.25Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path
        d="M13.5 2.9V7.75H18.35"
        stroke="currentColor"
        strokeOpacity="0.64"
        strokeWidth="1.75"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M8.75 12.25H15.25M8.75 15.75H13"
        stroke="currentColor"
        strokeOpacity="0.46"
        strokeWidth="1.6"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Minimal geometric lock with dual-tone chamber. */
export function IconLock({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect
        x="4.75"
        y="10.5"
        width="14.5"
        height="10"
        rx="2.6"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M8 10.5V7.75C8 5.54 9.79 3.75 12 3.75C14.21 3.75 16 5.54 16 7.75V10.5"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
      <circle cx="12" cy="15.5" r="1.25" fill="currentColor" />
    </svg>
  );
}

/** Quarantine warning diamond. */
export function IconQuarantine({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M12 2.75L21.25 12L12 21.25L2.75 12L12 2.75Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path d="M12 8V12.75" stroke="currentColor" strokeWidth="2" strokeLinecap="round" />
      <circle cx="12" cy="16" r="1.15" fill="currentColor" />
    </svg>
  );
}

/** Verified shield-check badge for quarantine-clear & declassification gates. */
export function IconShieldCheck({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M12 3L19.5 6.2V11.8C19.5 16.4 16.3 19.7 12 21.25C7.7 19.7 4.5 16.4 4.5 11.8V6.2L12 3Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path
        d="M8.75 12.25L11 14.5L15.5 9.75"
        stroke="currentColor"
        strokeWidth="1.95"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Precision search reticle. */
export function IconSearch({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="10.75"
        cy="10.75"
        r="6.75"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M15.8 15.8L20.5 20.5"
        stroke="currentColor"
        strokeWidth="1.95"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Clean geometric close cross. */
export function IconClose({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M6 6L18 18M18 6L6 18"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Precision directional chevron (default down). */
export function IconChevron({
  direction = "down",
  className,
  ...props
}: IconProps & { direction?: "down" | "right" | "up" | "left" }) {
  const path =
    direction === "right"
      ? "M9.25 6.25L15 12L9.25 17.75"
      : direction === "up"
        ? "M6.25 14.75L12 9L17.75 14.75"
        : direction === "left"
          ? "M14.75 6.25L9 12L14.75 17.75"
          : "M6.25 9.25L12 15L17.75 9.25";
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d={path}
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Crisp check mark. */
export function IconCheck({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M4.75 12.5L9.5 17.25L19.25 7.25"
        stroke="currentColor"
        strokeWidth="2"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Minimal dual-plane copy sheets. */
export function IconCopy({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect
        x="8.25"
        y="8.25"
        width="11.75"
        height="11.75"
        rx="2.5"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M15.75 8.25V6.25C15.75 5.01 14.74 4 13.5 4H6.25C5.01 4 4 5.01 4 6.25V13.5C4 14.74 5.01 15.75 6.25 15.75H8.25"
        stroke="currentColor"
        strokeOpacity="0.6"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Side inspector panel toggle. */
export function IconPanel({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path
        d="M14.75 4.25H18.25C19.77 4.25 21 5.48 21 7V17C21 18.52 19.77 19.75 18.25 19.75H14.75V4.25Z"
        fill="currentColor"
        fillOpacity="0.14"
      />
      <rect
        x="3"
        y="4.25"
        width="18"
        height="15.5"
        rx="2.75"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path d="M14.75 4.5V19.5" stroke="currentColor" strokeWidth="1.85" />
    </svg>
  );
}

/** Containment block ring for exfiltration blocks. */
export function IconBlock({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="12"
        cy="12"
        r="8.25"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M6.35 17.65L17.65 6.35"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Timer ring for JIT TTL approvals. */
export function IconClock({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="12"
        cy="12"
        r="8.25"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path
        d="M12 7.25V12.25L15.6 14.25"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Squash-declassify merge prism. */
export function IconDeclassify({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path d="M5 5.25H19L12 12L5 5.25Z" fill="currentColor" fillOpacity="0.12" />
      <path
        d="M5 5.25L12 12L19 5.25M12 12V17.5"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="19" r="2.1" fill="currentColor" />
    </svg>
  );
}

/** Responsive navigation drawer trigger. */
export function IconMenu({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <path d="M4 6.75H20" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path d="M4 12H20" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path
        d="M4 17.25H15.5"
        stroke="currentColor"
        strokeOpacity="0.78"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Crisp 4-pane Fluent Windows geometry. */
export function IconWindows({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect x="3" y="3" width="7.25" height="7.25" rx="1.35" fill="currentColor" fillOpacity="0.14" stroke="currentColor" strokeWidth="1.85" />
      <rect x="13.75" y="3" width="7.25" height="7.25" rx="1.35" fill="currentColor" fillOpacity="0.14" stroke="currentColor" strokeWidth="1.85" />
      <rect x="3" y="13.75" width="7.25" height="7.25" rx="1.35" fill="currentColor" fillOpacity="0.14" stroke="currentColor" strokeWidth="1.85" />
      <rect x="13.75" y="13.75" width="7.25" height="7.25" rx="1.35" fill="currentColor" fillOpacity="0.14" stroke="currentColor" strokeWidth="1.85" />
    </svg>
  );
}

/** Crisp macOS Command clover geometric mark. */
export function IconMacOS({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect x="9" y="9" width="6" height="6" fill="currentColor" fillOpacity="0.14" />
      <path
        d="M9 9H6.25A2.75 2.75 0 1 1 9 6.25V17.75A2.75 2.75 0 1 1 6.25 15H17.75A2.75 2.75 0 1 1 15 17.75V6.25A2.75 2.75 0 1 1 17.75 9H9Z"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Crisp Linux terminal/kernel emblem. */
export function IconLinux({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect
        x="3"
        y="4.25"
        width="18"
        height="15.5"
        rx="3"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <path d="M7.5 9.25L10.75 12L7.5 14.75" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M12.75 14.75H16.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** Renders the appropriate OS emblem automatically for `macos`, `windows`, or `linux`. */
export function IconOSBadge({ os, ...props }: IconProps & { os?: ClientOS }) {
  const detectedOS = useClientOS();
  const resolvedOS = os ?? detectedOS;

  switch (resolvedOS) {
    case "macos":
      return <IconMacOS {...props} />;
    case "windows":
      return <IconWindows {...props} />;
    case "linux":
      return <IconLinux {...props} />;
  }
}

/** Razor-sharp borderless git-ref glyph (designed to sit cleanly inside pills without double borders). */
export function IconBranchRef({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle cx="7.5" cy="12" r="2.35" fill="currentColor" fillOpacity="0.2" stroke="currentColor" strokeWidth="1.85" />
      <circle cx="17" cy="7.25" r="2.1" fill="currentColor" fillOpacity="0.16" stroke="currentColor" strokeWidth="1.85" />
      <circle cx="17" cy="16.75" r="2.1" fill="currentColor" fillOpacity="0.16" stroke="currentColor" strokeWidth="1.85" />
      <path
        d="M9.85 12C12.1 12 12.6 7.25 14.9 7.25M9.85 12C12.1 12 12.6 16.75 14.9 16.75"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
      />
    </svg>
  );
}

/** Soft word-wrap toggle icon. */
export function IconWrap({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M4 6.5H20" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path d="M4 12H16.5C18.43 12 20 13.34 20 15C20 16.66 18.43 18 16.5 18H12.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M14.5 15.5L11.75 18L14.5 20.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4 17.5H8.5" stroke="currentColor" strokeOpacity="0.6" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** Collapse/fold all nodes. */
export function IconFold({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M7.5 5.5L12 10L16.5 5.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M7.5 18.5L12 14L16.5 18.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4.5 12H19.5" stroke="currentColor" strokeOpacity="0.45" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

/** Expand/unfold all nodes. */
export function IconUnfold({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M7.5 9.25L12 4.75L16.5 9.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M7.5 14.75L12 19.25L16.5 14.75" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Refresh / reconnect arc. */
export function IconRefresh({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M19.5 12A7.5 7.5 0 1 1 17.3 6.7L20 9.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M20 4.75V9.25H15.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Link / line permalink icon. */
export function IconLink({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M10.25 13.75L13.75 10.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path d="M8.5 16.5L7.1 17.9A3.5 3.5 0 0 1 2.15 12.95L5.2 9.9A3.5 3.5 0 0 1 10.15 9.9" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path d="M15.5 7.5L16.9 6.1A3.5 3.5 0 0 1 21.85 11.05L18.8 14.1A3.5 3.5 0 0 1 13.85 14.1" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** Download / export artifact icon. */
export function IconDownload({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M12 4.5V15M12 15L8 11M12 15L16 11" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4.5 17.25V18.5C4.5 19.33 5.17 20 6 20H18C18.83 20 19.5 19.33 19.5 18.5V17.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** Crisp plus glyph. */
export function IconPlus({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M12 5.25V18.75M5.25 12H18.75" stroke="currentColor" strokeWidth="1.95" strokeLinecap="round" />
    </svg>
  );
}

/** Crisp CLI terminal icon. */
export function IconTerminal({ className, ...props }: IconProps) {
  return <IconLinux className={className} {...props} />;
}

/** Precision diagonal edit stylus. */
export function IconEdit({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path
        d="M4.5 19.5L8.25 18.6L18.4 8.45C19.2 7.65 19.2 6.35 18.4 5.55L18.45 5.6C17.65 4.8 16.35 4.8 15.55 5.6L5.4 15.75L4.5 19.5Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path d="M13.75 7.4L16.6 10.25" stroke="currentColor" strokeOpacity="0.65" strokeWidth="1.7" strokeLinecap="round" />
    </svg>
  );
}

/** Crisp geometric trash bin for branch delete / secret revoke / overlay unmount. */
export function IconTrash({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M4.5 7H19.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path d="M9.25 4.25H14.75" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <path
        d="M6.75 7L7.55 18.2C7.64 19.22 8.49 20 9.51 20H14.49C15.51 20 16.36 19.22 16.45 18.2L17.25 7"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path d="M10.25 10.75V16M13.75 10.75V16" stroke="currentColor" strokeOpacity="0.65" strokeWidth="1.65" strokeLinecap="round" />
    </svg>
  );
}

/** Crisp play triangle for launching live caged sessions & publishing. */
export function IconPlay({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path
        d="M7 5.25L18.5 12L7 18.75V5.25Z"
        fill="currentColor"
        fillOpacity="0.18"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Inline review comment bubble. */
export function IconComment({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path
        d="M4.25 6.5C4.25 5.26 5.26 4.25 6.5 4.25H17.5C18.74 4.25 19.75 5.26 19.75 6.5V14.25C19.75 15.49 18.74 16.5 17.5 16.5H10.25L6 19.75V16.5H6.5C5.26 16.5 4.25 15.49 4.25 14.25V6.5Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path d="M8.5 9.25H15.5M8.5 12.25H13" stroke="currentColor" strokeOpacity="0.65" strokeWidth="1.65" strokeLinecap="round" />
    </svg>
  );
}

/** Git blame gutter rail icon. */
export function IconBlame({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <rect x="3.5" y="4.5" width="6.5" height="15" rx="1.75" fill="currentColor" fillOpacity="0.16" stroke="currentColor" strokeWidth="1.85" />
      <path d="M13 7.5H20.5M13 12H19M13 16.5H20.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** GitHub companion mark: a glass disc with the octocat-free branch-fork glyph. */
export function IconGithub({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <circle cx="12" cy="12" r="8.75" fill="currentColor" fillOpacity="0.12" stroke="currentColor" strokeWidth="1.85" />
      <circle cx="9" cy="8.5" r="1.35" fill="currentColor" />
      <circle cx="9" cy="15.5" r="1.35" fill="currentColor" />
      <circle cx="15" cy="10.5" r="1.35" fill="currentColor" />
      <path d="M9 9.9V14.1M15 11.9C15 13.5 13.6 13.9 12 13.9C10.4 13.9 9 14.3 9 14.1" stroke="currentColor" strokeWidth="1.65" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Bidirectional sync: two opposed arcs with arrowheads. */
export function IconSync({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M4.5 10.5A7.5 7.5 0 0 1 17.6 6.9L19.5 8.75" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M19.5 4.5V8.75H15.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M19.5 13.5A7.5 7.5 0 0 1 6.4 17.1L4.5 15.25" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
      <path d="M4.5 19.5V15.25H8.75" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Dual-plane mirror lens: one solid half, one open half, split by the Glass Wall. */
export function IconSplitLens({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M12 3.75A8.25 8.25 0 0 0 12 20.25Z" fill="currentColor" fillOpacity="0.16" />
      <circle cx="12" cy="12" r="8.25" stroke="currentColor" strokeWidth="1.85" />
      <path d="M12 2.5V21.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
      <circle cx="15.75" cy="12" r="1.6" fill="currentColor" fillOpacity="0.68" />
    </svg>
  );
}

/** Policy shield with a faint interior plane. */
export function IconShield({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path
        d="M12 3.5L19 6.25V11.5C19 15.75 16.1 19.1 12 20.5C7.9 19.1 5 15.75 5 11.5V6.25L12 3.5Z"
        fill="currentColor"
        fillOpacity="0.14"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <path d="M9 11.75L11.25 14L15.25 9.75" stroke="currentColor" strokeOpacity="0.68" strokeWidth="1.85" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Crisp geometric eye for the Left/Right reality labels. */
export function IconEye({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path
        d="M2.75 12C4.6 7.9 8 5.75 12 5.75C16 5.75 19.4 7.9 21.25 12C19.4 16.1 16 18.25 12 18.25C8 18.25 4.6 16.1 2.75 12Z"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinejoin="round"
      />
      <circle cx="12" cy="12" r="2.9" stroke="currentColor" strokeWidth="1.85" />
      <circle cx="12" cy="12" r="1" fill="currentColor" />
    </svg>
  );
}

/** Six-dot drag grip for the Glass Wall divider handle. */
export function IconGripVertical({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <g fill="currentColor">
      <circle cx="9" cy="6.5" r="1.45" />
      <circle cx="15" cy="6.5" r="1.45" />
      <circle cx="9" cy="12" r="1.45" />
      <circle cx="15" cy="12" r="1.45" />
      <circle cx="9" cy="17.5" r="1.45" />
      <circle cx="15" cy="17.5" r="1.45" />
      </g>
    </svg>
  );
}

/** Chronological scrubber rail with step nodes for Session Replay. */
export function IconTimeline({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path d="M7 4.75V19.25" stroke="currentColor" strokeOpacity="0.55" strokeWidth="1.85" strokeLinecap="round" />
      <circle cx="7" cy="6.75" r="2.25" fill="currentColor" fillOpacity="0.22" stroke="currentColor" strokeWidth="1.85" />
      <circle cx="7" cy="12" r="2.25" fill="currentColor" fillOpacity="0.22" stroke="currentColor" strokeWidth="1.85" />
      <circle cx="7" cy="17.25" r="2.25" fill="currentColor" fillOpacity="0.22" stroke="currentColor" strokeWidth="1.85" />
      <path d="M12.25 6.75H19.5M12.25 12H17.5M12.25 17.25H19.5" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** Guided tour waypoint / semantic walkthrough compass. */
export function IconCompass({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <circle cx="12" cy="12" r="8.25" fill="currentColor" fillOpacity="0.12" stroke="currentColor" strokeWidth="1.85" />
      <path
        d="M14.95 9.05L13.3 13.3L9.05 14.95L10.7 10.7L14.95 9.05Z"
        fill="currentColor"
        fillOpacity="0.26"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinejoin="round"
      />
    </svg>
  );
}

/** Directed shoulder-tap / steering vector chevron. */
export function IconSteer({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <path
        d="M4.5 16.5V11.25C4.5 8.9 6.4 7 8.75 7H19"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <path
        d="M15.25 3.75L19.5 7L15.25 10.25"
        stroke="currentColor"
        strokeWidth="1.85"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
      <circle cx="4.5" cy="17.75" r="2" fill="currentColor" fillOpacity="0.22" stroke="currentColor" strokeWidth="1.75" />
    </svg>
  );
}

/** Concentric risk & drift radar arcs. */
export function IconRadar({ className, ...props }: IconProps) {
  return (
    <svg viewBox="0 0 24 24" fill="none" shapeRendering="geometricPrecision" aria-hidden="true" className={resolveIconClass(className)} {...props}>
      <circle cx="12" cy="12" r="8.25" fill="currentColor" fillOpacity="0.1" stroke="currentColor" strokeOpacity="0.65" strokeWidth="1.75" />
      <circle cx="12" cy="12" r="4.65" stroke="currentColor" strokeOpacity="0.82" strokeWidth="1.65" />
      <circle cx="12" cy="12" r="1.65" fill="currentColor" />
      <path d="M12 12L17.6 6.4" stroke="currentColor" strokeWidth="1.85" strokeLinecap="round" />
    </svg>
  );
}

/** Crisp geometric pause bars for pausing live caged sessions & stepping in. */
export function IconPause({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <rect
        x="5.75"
        y="4.75"
        width="4.5"
        height="14.5"
        rx="1.4"
        fill="currentColor"
        fillOpacity="0.16"
        stroke="currentColor"
        strokeWidth="1.85"
      />
      <rect
        x="13.75"
        y="4.75"
        width="4.5"
        height="14.5"
        rx="1.4"
        fill="currentColor"
        fillOpacity="0.16"
        stroke="currentColor"
        strokeWidth="1.85"
      />
    </svg>
  );
}

/** Quiet concentric geometric telemetry pulse for ambient security hygiene. */
export function IconAmbientPulse({ className, ...props }: IconProps) {
  return (
    <svg
      viewBox="0 0 24 24"
      fill="none"
      shapeRendering="geometricPrecision"
      aria-hidden="true"
      className={resolveIconClass(className)}
      {...props}
    >
      <circle
        cx="12"
        cy="12"
        r="8.25"
        stroke="currentColor"
        strokeOpacity="0.34"
        strokeWidth="1.85"
      />
      <circle
        cx="12"
        cy="12"
        r="4.85"
        fill="currentColor"
        fillOpacity="0.12"
        stroke="currentColor"
        strokeOpacity="0.72"
        strokeWidth="1.85"
      />
      <circle cx="12" cy="12" r="1.85" fill="currentColor" />
    </svg>
  );
}
