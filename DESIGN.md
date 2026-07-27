---
version: alpha
name: LLM Notary
description: A high-contrast, editorial product system for independently verifiable LLM traces.
colors:
  primary: "#101010"
  accent: "#B9FF38"
  accent-ink: "#315400"
  light-surface: "#F6F5F2"
  light-surface-raised: "#FFFFFF"
  light-border: "#D8D7D2"
  light-muted: "#6E6D68"
  dark-surface: "#171717"
  dark-surface-raised: "#202020"
  dark-surface-subtle: "#2C2C2C"
  dark-border: "#484848"
  dark-muted: "#B8B8B8"
  dark-on-surface: "#F6F6F6"
  white: "#FFFFFF"
typography:
  display-lg:
    fontFamily: Manrope
    fontSize: 96px
    fontWeight: 800
    lineHeight: 0.96
    letterSpacing: -0.085em
  headline-lg:
    fontFamily: Manrope
    fontSize: 62px
    fontWeight: 800
    lineHeight: 1.04
    letterSpacing: -0.07em
  headline-md:
    fontFamily: Manrope
    fontSize: 36px
    fontWeight: 700
    lineHeight: 1.04
    letterSpacing: -0.07em
  body-md:
    fontFamily: Manrope
    fontSize: 16px
    fontWeight: 400
    lineHeight: 1.6
  body-sm:
    fontFamily: Manrope
    fontSize: 14px
    fontWeight: 400
    lineHeight: 1.65
  label-md:
    fontFamily: Manrope
    fontSize: 13px
    fontWeight: 700
    lineHeight: 1
  label-caps:
    fontFamily: DM Mono
    fontSize: 11px
    fontWeight: 500
    lineHeight: 1
    letterSpacing: 0.07em
spacing:
  xs: 4px
  sm: 8px
  md: 16px
  lg: 24px
  xl: 32px
  xxl: 48px
  section-mobile: 75px
  section-desktop: 115px
rounded:
  none: 0px
  full: 9999px
components:
  button-primary:
    backgroundColor: "{colors.primary}"
    textColor: "{colors.white}"
    rounded: "{rounded.none}"
    padding: "14px 18px"
    typography: "{typography.label-md}"
  button-secondary:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.primary}"
    rounded: "{rounded.none}"
    padding: "14px 18px"
    typography: "{typography.label-md}"
  card:
    backgroundColor: "{colors.light-surface-raised}"
    textColor: "{colors.primary}"
    rounded: "{rounded.none}"
  popover:
    backgroundColor: "{colors.light-surface-raised}"
    textColor: "{colors.primary}"
    border: "1px solid {colors.light-border}"
    rounded: "{rounded.none}"
    shadow: none
  status-marker:
    backgroundColor: "{colors.accent}"
    textColor: "{colors.accent-ink}"
    size: 10px
    rounded: "{rounded.full}"
  text-secondary-light:
    backgroundColor: "{colors.light-surface}"
    textColor: "{colors.light-muted}"
  surface-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-on-surface}"
  surface-dark-raised:
    backgroundColor: "{colors.dark-surface-raised}"
    textColor: "{colors.dark-on-surface}"
  surface-dark-subtle:
    backgroundColor: "{colors.dark-surface-subtle}"
    textColor: "{colors.dark-on-surface}"
  text-secondary-dark:
    backgroundColor: "{colors.dark-surface}"
    textColor: "{colors.dark-muted}"
  rule-light:
    backgroundColor: "{colors.light-border}"
    textColor: "{colors.primary}"
  rule-dark:
    backgroundColor: "{colors.dark-border}"
    textColor: "{colors.dark-on-surface}"
---

## Overview

LLM Notary should feel precise, private, and independently verifiable: more like a carefully typeset research record than a conventional AI product. Use an editorial, high-contrast composition with generous breathing room, thin rules, and sparse use of a single lime accent. The visual voice is calm and institutional, not glossy, playful, or futuristic. The intended audience is researchers, evaluators, and technical teams who need evidence they can inspect and trust.

## Colors

The system is built from neutral near-black, warm paper, white, and gray; lime is the only chromatic accent. The light and dark modes are both first-class surfaces, selected through `prefers-color-scheme`. Dark mode must remain strictly neutral gray/black—never olive, green, or warm-tinted.

- **Primary:** use `primary` for core light-mode text and inverse panels.
- **Surfaces:** use the `light-*` or `dark-*` surface and border tokens as a set; do not mix modes within one surface.
- **Accent:** reserve `accent` for verified/status markers, the pen-mark contrast, and a small number of high-value headings or code details. It is not a general-purpose background color.
- **Muted content:** use the matching mode’s muted token for metadata, labels, and secondary copy; keep primary reading text at full contrast.

## Typography

Use **Manrope** for all narrative text, navigation, controls, and headings. Headlines are bold and tightly tracked, with display copy permitted to break across lines for an editorial rhythm. Use **DM Mono** only for compact technical context: section kickers, labels, metadata, timestamps, command output, and receipt fields. Uppercase mono labels should be small and visibly letter-spaced; never set paragraphs in mono.

Use `display-lg` only for page heroes. Use `headline-lg` for primary section titles and `headline-md` for cards, receipts, and document titles. Keep body copy readable and restrained; dense proof data should use `label-caps` or a related small mono treatment.

## Layout

Use a fluid desktop layout with viewport-relative horizontal padding and generous vertical section spacing. Default desktop sections use `section-desktop`; mobile sections use `section-mobile` with 25px side padding. Major sections may use two columns, but collapse to one column at 820px and below. Align content to rules, card edges, and column starts rather than centering every element.

Collections and documentation share a `1320px` maximum content width, 38px desktop side padding, and a 46px top offset below the navigation. Collections are a browse workspace: start with search, filters, and topic chips—do not add a marketing hero or explanatory page headline above those controls. On desktop, pair the result list and persistent inspector in a 1.15 / 0.85 column grid with a 32px gutter. Documentation uses the same outer width and gutter, with a compact sticky navigation column and a constrained reading column; it should feel like a sibling view, not a separate site.

Use the spacing scale consistently: `sm` for icon/text gaps, `md` for ordinary component gaps, `lg`–`xxl` for group separation, and the section tokens for page rhythm. Tables, receipts, and result lists use thin dividers rather than extra card nesting.

## Elevation & Depth

This is a flat system. Create hierarchy with surface contrast, 1px borders, spacing, and typographic weight—not soft shadows or floating glass effects. A deliberate hard offset shadow is allowed only for a transient modal, where it reinforces the document-like, physical-paper motif. Sticky navigation may use a subtle backdrop blur, but it must keep the underlying mode’s surface color.

## Shapes

Rectangular containers, buttons, inputs, cards, and rules are square (`rounded.none`). Use `rounded.full` only for small status markers and the circular pen mark. The pen mark is a black circular badge with a white line-drawn pen; keep that relationship intact in the favicon and in-product marks. Do not introduce pill-shaped buttons, rounded cards, or unrelated decorative icon styles.

## Components

- **Navigation:** quiet text links, with one outlined destination when a stronger affordance is useful. Keep the pen mark at the left and avoid a crowded top bar.
- **Buttons and links:** primary actions are solid black with white text in light mode and solid near-black with light text in dark mode. Secondary actions are text-first or outlined. Use simple color and border changes for hover; keep labels concise and direct.
- **Cards and lists:** use raised surfaces, square corners, and 1px borders. Trace rows and collection entries should expose evidence context through compact metadata, a `Verified` marker, and clear scanning hierarchy. Do not call the collection status “platform-stamped” in UI labels; the stamp is the underlying proof mechanism, while `Verified` is the reader-facing state.
- **Selection and hover:** collection cards and trace rows are stable documents, not floating controls. Do not translate, scale, or add elevation on hover. Use a persistent active state, a thin rule, or a restrained surface change to show selection; retain visible keyboard focus.
- **Receipts and terminal blocks:** inverse, near-black panels with monospace metadata and restrained lime highlights. They should read as technical evidence, not as decorative code samples.
- **Forms and dialogs:** retain square input fields, visible borders, and a strong focus ring. Modal backdrops can dim and blur the page, but the dialog remains a paper-like surface.
- **Popovers and menus:** anchor them to their trigger with a small gap. Use a raised surface, a matching-mode 1px border, and an internal divider for identity or grouping. Do not add a drop shadow, glass effect, page backdrop, or decorative caret; outside click and Escape should dismiss them.
- **System theme:** new UI must work in both system modes without a manual theme toggle unless product requirements add one. Put reusable mode values in semantic CSS custom properties rather than introducing ad hoc mode-specific literals.

## Do's and Don'ts

- Do preserve WCAG AA contrast for normal text and visible keyboard focus in both themes.
- Do let lime signal verification, readiness, or a single focal point.
- Do use real content, proof fields, and intentional whitespace to build confidence.
- Do test desktop and mobile at the 820px breakpoint, plus light and dark system preferences.
- Don't add gradients, neon glows, glass cards, or generic AI imagery.
- Don't tint dark neutrals toward olive, brown, or green; lime is the sole color accent.
- Don't use more than Manrope and DM Mono, or mix rounded and square rectangular components.
- Don't use lime for long-form text, large backgrounds, or several competing calls to action on one screen.
