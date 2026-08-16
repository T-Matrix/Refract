# Refract Design System

**Reference:** OpenFlare default console theme
**Stack:** Embedded HTML, CSS, and JavaScript
**Density:** 8/10, compact operations dashboard
**Motion:** 2/10, functional transitions only

## Principles

- Use neutral work surfaces with one violet primary accent.
- Keep the product dense, quiet, and optimized for repeated operational work.
- Use dashed borders and little or no elevation for dashboard sections.
- Keep page sections unframed; frame only datasets, maps, forms, and repeated metrics.
- Use Lucide outline icons consistently. Do not use emoji as interface icons.
- Never depend on color alone for status; pair color with text or an icon.

## Shell

- Desktop sidebar: 240px expanded, 64px collapsed, fixed to the left.
- Sidebar header: signed-in account and Refract icon.
- Sidebar groups: Reverse Proxy, Security, and Administration.
- Sidebar footer: product name and version.
- Top toolbar: page search, settings, full-width toggle, and theme toggle.
- Content: max-width 1320px, with a user-controlled full-width mode.
- Mobile: sidebar becomes an off-canvas drawer; do not use bottom navigation.

## Color Tokens

| Role | Light | Dark |
|---|---|---|
| Background | `#ffffff` | `#18181b` |
| Subtle surface | `#fafafa` | `#202023` |
| Muted surface | `#f4f4f5` | `#27272a` |
| Foreground | `#18181b` | `#fafafa` |
| Muted foreground | `#71717a` | `#a1a1aa` |
| Border | `#e4e4e7` | `#343438` |
| Strong border | `#d4d4d8` | `#48484f` |
| Primary | `#635bff` | `#8c85ff` |
| Primary surface | `#f0efff` | `#302f53` |
| Success | `#16835c` | `#67c69c` |
| Warning | `#a16207` | `#e6b85f` |
| Destructive | `#c2413a` | `#f1847e` |

## Typography

- Font stack: system UI, Segoe UI, Noto Sans SC, sans-serif.
- Page title: 24px / 650.
- Section title: 14px / 650.
- Body: 12-14px.
- Metadata: 10-11px with sufficient contrast.
- Numeric metrics use tabular figures.
- Letter spacing is always 0.

## Components

- Primary button: violet fill, 36px desktop height, 44px touch height, 6px radius.
- Outline button: neutral border and background, minimal shadow.
- Icon button: 36x36px desktop, 44x44px touch, always has `aria-label` and tooltip.
- Input/select: 36px desktop, 44px touch, 6px radius, 2px focus ring.
- Card/tool surface: 1px dashed strong border, 8px radius, no shadow.
- Table: 44px rows, 11px headers, horizontal overflow wrapper on narrow screens.
- Segmented control: muted track with a raised white selected item.
- Switch: compact pill with visible focus and disabled states.
- Dialog: native modal behavior, 8px radius, 48% black backdrop.

## Dashboard

- Put real-time metrics, world map, period selection, and region summary into one situation board.
- The map supports drag, zoom, and reset controls.
- Chinese traffic aggregates by province; other traffic aggregates by country.
- Geographic charts must have equivalent sortable tables directly below them.
- Keep exact values visible; tooltips are supplementary.

## Responsive Rules

- 1220px and below: metric grid becomes three columns.
- 1040px and below: map and region summary stack vertically.
- 840px and below: desktop sidebar becomes an off-canvas drawer.
- 600px and below: metric grid becomes two columns and all touch targets reach 44px.
- Test 375, 768, 1024, and 1440 widths with no page-level horizontal overflow.

## Accessibility

- Include a skip link before navigation.
- Keep visible focus rings on every interactive control.
- Use native buttons, inputs, radio controls, dialog, and table semantics.
- Respect `prefers-reduced-motion`.
- Maintain at least 4.5:1 contrast for body text and 3:1 for large text/icons.
- Every icon-only action requires both `aria-label` and `title`.

## Avoid

- Decorative gradients, large shadows, floating marketing sections, and oversized type.
- Nested decorative cards, layout-shifting hover transforms, and color-only status.
- Runtime CDN dependencies, emoji icons, and hidden functionality on mobile.
