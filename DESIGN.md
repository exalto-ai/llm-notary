---
version: beta
name: Notary by Exalto / Axis
description: A compact evidence workspace for people who need to find, inspect, notarize, and verify LLM interactions without ceremony.
colors:
  canvas: "#FFFFFF"
  surface: "#FFFFFF"
  surface-active: "#F2F2F2"
  section-muted: "#F5F5F5"
  ink: "#101010"
  muted: "#6B6B6B"
  rule: "#D4D4D4"
  rule-soft: "#E7E7E7"
  action: "#1C55CD"
  action-ink: "#143D94"
  action-soft: "#B9D8FF"
  action-fill: "#1C55CD"
  action-fill-hover: "#143D94"
  action-contrast: "#FFFFFF"
  inverse-accent: "#B9D8FF"
  attention: "#A85F25"
  attention-soft: "#F4C27C"
  dark-canvas: "#000000"
  dark-surface: "#0B0B0B"
  dark-surface-active: "#171717"
  dark-section-muted: "#0B0B0B"
  dark-ink: "#F5F5F5"
  dark-muted: "#A0A0A0"
  dark-rule: "#2C2C2C"
  dark-action: "#6D92FF"
  dark-action-ink: "#A9BEFF"
  dark-action-soft: "#1A2340"
  dark-action-fill: "#1C55CD"
  dark-action-fill-hover: "#285FD1"
  dark-action-contrast: "#FFFFFF"
  dark-inverse-accent: "#B9D8FF"
typography:
  display:
    fontFamily: "Instrument Sans Variable"
    fontWeight: 600
    letterSpacing: "-0.05em"
    lineHeight: 0.93
  interface:
    fontFamily: "Instrument Sans Variable"
    fontWeight: 400
    lineHeight: 1.45
  data:
    fontFamily: "IBM Plex Mono"
    fontWeight: 500
    letterSpacing: "0.05em"
    lineHeight: 1.3
shape:
  controlRadius: 0px
  markRadius: 5px
  statusRadius: 0px
  shadow: none
layout:
  desktopGutter: 16px
  compactGutter: 12px
  pageMax: none
  controlHeight: 34px
  navigationHeight: 50px
  rowHeight: 57px
  splitRailDefault: 320px
  splitRailRange: 272–460px
---

# Notary design language

## Product posture

Notary is evidence infrastructure. Its audience already understands model providers, local tooling, and the difference between a claim and a record. The interface’s job is to make the next accountable action obvious: capture, inspect, notarize, verify, or share.

Axis should feel like a precise instrument panel built around an evidence record. It is cool, compact, legible, and calm. It must never read like a generic AI product, a marketing dashboard, or a document with decorative metadata.

The visual signature is the indigo rounded-square pen mark. It appears as the favicon and the smallest brand identifier. The ordinary product name is `Notary`; the formal standalone identity is `Notary by Exalto`, with `Notary` visually dominant and `by Exalto` subordinate. The normal mark keeps roughly 11% inset around the pen; the favicon uses roughly 21% so the pen remains legible instead of touching the browser chrome. Everything else stays quiet enough for the evidence itself to lead.

## The governing rule: start with the work

Do not begin a product screen with a large page title, a subheading, an eyebrow, or an explanatory paragraph unless that text changes what the user can do. A capture list begins with its controls and rows. A trace begins with the trace. A settings screen begins with the setting.

Navigation, filters, data, selection, and the next irreversible action may occupy the screen. Promotional copy, repeated privacy assurances, decorative counters, “next action” labels, and empty filler must not.

When a privacy or trust boundary matters, show it at the exact decision point as a concise fact. For example, `Request — Private on this device` belongs in a capture inspector. `Nothing is published automatically` does not belong in a sidebar footer.

## Color

Axis is monochrome by default. Light mode starts from true white; dark mode starts from true black. Neutral surfaces and structure use only grays. Blue is a signal, never an atmosphere.

- `canvas` is the broad application field: white in light mode and black in dark mode.
- `surface` is an active reading or working plane. It is not automatically a card and must not carry a blue tint.
- `surface-active` marks the selected row or focused local record.
- `section-muted` separates long public-page chapters from their neighbors. It is a near-white gray in light mode and charcoal in dark mode, never a tint of the action color.
- `ink` carries all primary text, rules that need emphasis, and dark actions.
- `muted` carries timestamps, provider/model metadata, secondary labels, and inactive navigation.
- `rule` and `rule-soft` make structure visible. Prefer a rule between objects over a frame around every object.
- `action` is the bright signal blue used for selected navigation, focus, status markers, and other small highlights. It is not a large text-bearing background.
- `action-fill` is the deeper indigo used for solid primary controls. It always carries white `action-contrast` text in both themes.
- `inverse-accent` is the pale blue used when technical text must be chromatic on a black surface. The normal action blue is too dark for small text on black.
- `attention` is reserved for an actionable problem. Do not use it as a second brand color.

Dark mode preserves the same hierarchy with black and charcoal surfaces and neutral white text. Never use navy as a default surface. Never reintroduce gradients, glow, or warm cream. The action blue must remain the only saturated default color; attention colors appear only for real warnings or failures.

Do not put black text on a saturated blue control. Do not darken text just to make the brighter signal blue usable as a large fill. Instead, keep signal blue bright and small, and use the deeper `action-fill` with white text for buttons, selected filter controls, and dialog confirmations. On black receipts, animation nodes, terminals, or code examples, use neutral white for ordinary text and `inverse-accent` only for the small technical value that needs emphasis. Normal text, status labels, and controls must meet at least WCAG AA contrast in both modes.

## Typography

Use two families across three roles, each with a narrow job:

- **Instrument Sans Variable** is both the display and interface face. Use scale, weight, and spacing—not a second sans-serif—to distinguish a page thesis or record title from navigation, controls, body copy, and buttons. It should never be set like dense operational data.
- **IBM Plex Mono** is the evidence face. Use it for identifiers, status, provider/model strings, timestamps, field names, counts, code, and compact contextual labels.

Typical sizes:

| Role | Desktop | Use |
| --- | ---: | --- |
| Display | 52–78px | One landing-page thesis only |
| Record title | 24–32px | Selected record or document title |
| Section title | 20–24px | Only when a screen contains more than one real group |
| Interface | 12–16px | Rows, controls, navigation, and body copy |
| Data label | 9–11px | IDs, states, times, and field names |

Do not use all-caps as texture. Uppercase mono labels exist only where a field name or a compact system state makes scanning faster.

## Layout and density

Desktop product views are edge-to-edge workspaces with a **16px outer gutter** at most. There is no centered 1320px product shell and no large left/right emptiness. On narrow screens, reduce the outer gutter to 12px and let content become a natural document scroll.

The standard browse view has four bands:

```
compact navigation + one primary action
search / state / sort / result range
results list                         selected inspector
rows, rules, and facts               record facts + action
```

The operational navigation bar is 50px tall; the public site may use 54px when its sign-in action needs the extra height. Controls are 34px tall. Dense result rows are approximately 57px tall and use their columns to reveal title, provider/model, and time without opening a detail view. One vertical rule can divide a list from its inspector. Do not put either side inside a separate card.

The unified Traces list/inspector layout starts with a **320px list rail**. A 7px drag target on the dividing rule lets the user resize that rail from 272–460px; arrow keys move it in 16px increments, and the chosen width persists for the workspace. The inspector remains the flexible, dominant pane. If a list cannot fit at the standard width, redesign its row into two or three stacked comparison lines instead of widening the rail or forcing permanent horizontal scrolling. Entire rows open their record by pointer or keyboard. Do not reserve a trailing arrow column for navigation.

On mobile, remove the drag divider and let the list and inspector become sequential views. Keep filters visible at the top; replace dense columns with the two facts most useful to the current task. Never make a phone user horizontally scroll an operational table.

Marketing and documentation are allowed more space than operational UI, but they still align to an evidence path or reading column. A large hero must earn its space by stating the thesis, not by creating atmosphere. Separate major landing-page chapters by alternating `canvas` and `section-muted` backgrounds; do not stack full-width horizontal borders between every chapter.

Construct grids from one outer 1px `rule` and one 1px internal rule between adjacent cells. Do not mix an `ink` outer edge with `rule` inner edges, and do not overlap a container border with a child border—the result reads as uneven thickness, especially on dark surfaces and high-density displays.

## Components

### Brand and navigation

Use the rounded-square pen mark on the blue action background with a light pen. Preserve visible breathing room around the pen and increase it further at favicon sizes. The public wordmark is `Notary`. Use the endorsed `Notary by Exalto` lockup only where standalone ownership matters, keeping `Notary` dominant and `by Exalto` subordinate. The administration workspace uses the visible product name `Notary`, a quiet `Local admin` or `Cluster admin` context where needed, and the browser title `Admin · Notary by Exalto`.

Navigation is a single horizontal band. Active items use an indigo bottom rule or left rule, never a pill. A count may appear in mono when it changes a decision. Do not add a second sidebar when the top navigation already exposes the relevant destinations.

In the local workspace, the active tab is the page label. Begin each tab with its controls, status strip, list, or working content; do not repeat the tab name as an in-page heading. The mobile navigation contains only destinations and counts—never fixture/debug labels or passive branding.

### Buttons, links, and controls

Primary actions are rectangular `action-fill` controls with white `action-contrast` text in both themes. Bright `action` blue is not a button fill. Labels use direct verbs: `Notarize trace`, `Share trace`, `Revoke device`, `Copy URL`. A single screen should normally have one primary action.

Secondary actions are bordered or text-only. Filters and sort controls are square, bordered, and neutral until selected. Inputs have a visible 1px rule and no container behind them. Select chevrons keep at least 12px from the right edge. Do not use rounded pills, floating action buttons, icon-only actions without an accessible label, or fake disabled-looking controls.

Use shadcn components backed by Radix for behavior-heavy primitives: selects, command menus, dialogs, alerts, and future popovers or menus. Keep their accessibility and keyboard behavior; style them through Axis classes and semantic variables. A primitive is not permission to accept its default radius, shadow, spacing, or palette. Continue using existing application components where replacement would add no behavioral value.

### Lists, rows, and selection

Rows belong to a continuous list separated by rules. A selected row gets `surface-active` and a 3px indigo inset rule. Hover may alter the surface slightly, but it must not lift, scale, slide, or shadow.

Every list must show information people can compare. For captures this is title, provider/model, and capture time. For publication jobs this is state, trace title/ID, and date. For devices this is name and last use. Avoid “cards” with repeated labels and unused bottom space.

### Inspectors and evidence facts

An inspector is an attached reading panel, not a card. Put the identifier and state at its top, followed by the record title and its essential context. Render facts as compact horizontal rows:

```
REQUEST            Private on this device
PROVIDER SESSION   Authenticated TLS
NOTARIZATION       Not started
```

Facts must describe a real state or trust boundary. Do not restate a section title as prose below it.

### States, errors, empty views, and modal dialogs

Statuses use a small square outlined marker plus words. `Ready to notarize` and `Notarized` use blue; `Needs attention`, `Rejected`, and `Failed` use attention; neutral states use muted rules. Never use a status color without text.

Empty states state what is absent and offer the appropriate next action. Errors say what failed and expose a retry or recovery action. They do not apologize, use ellipses for mood, or imply background activity that is not happening.

Loading states preserve the geometry of the content that will replace them. In a list/inspector workspace, show quiet static row and fact placeholders in the existing columns—no centered loading card, spinner theater, shimmer, pulse, or layout jump.

Dialogs are flat surfaces with a hard 1px rule. They contain a clear question, the affected record, the consequence, and the two actual choices. Do not blur the whole application, add a marketing headline, or hide the destructive action behind vague wording. Use no drop shadows; a darkened backdrop is sufficient. Command search uses one continuous surface: the input boundary, result rows, and footer must not create nested focus boxes. The text cursor is enough to show that the search input is active.

### Documentation and public traces

Documentation is a reading surface with a compact sticky outline. Inline commands, filenames, configuration keys, route names, and literal values use a quiet mono inline-code treatment: neutral soft background, one neutral rule, and normal ink. Reserve the black block treatment for copyable multi-line examples. Do not leave technical tokens visually indistinguishable inside long prose, and do not turn ordinary product nouns into code.

Use artifact names precisely. A `.llmcapture` is private deferred state, a `.llmtrace` is the portable evidence package, and a bare Library trace is admitted output for inspection. Never label a capture verified or imply that the bare public JSON carries the package's cryptographic evidence. Put the request/response-body disclosure warning beside every upload or share action.

On mobile, the documentation toolbar attaches directly below the 54px public header. It is fully opaque, uses no outer padding above or below its control rows, and shares the header’s full-width rules so it reads as one piece of chrome. An open documentation menu must completely cover the article beneath it. Public trace browsing uses the same filter/list/inspector grammar as local captures. Do not surround every content block with a card. Use a code block only for code and a fact table only for verifiable facts.

Footer links remain visually quiet on pointer hover: no underline, color flash, translation, or animated decoration. Keyboard focus must remain clearly visible.

## Motion

Motion explains an evidence transition; it does not make the product feel alive.

- The landing hero may use the animated grid, but the animation is clipped to the hero and ends at that section boundary. The hero thesis sits below center but with roughly 15vh of space beneath it—low enough to preserve the signal field above, high enough that it does not feel pinned to the bottom. At display scale, use Instrument Sans Variable around `-0.025em`; tighter tracking makes “Verifiable intelligence” visibly cramped.
- The relay diagram must not inherit the hero grid. It presents only the motion needed to explain the request, notary, provider, and evidence path.
- The relay diagram keeps its data flow, but packets move in one deliberate pass and then rest. Avoid infinite typewriter effects, spinning controls, or repeated sealing theatrics.
- Selection, filters, menus, and dialogs may fade or change surface color over 120–160ms. They do not spring, scale, or float.
- Respect `prefers-reduced-motion`: show the final evidence state without movement.

## Copy

Write for a user who is deciding what to do with an evidence record. Use sentence case, direct nouns, specific verbs, and real state names.

Good: `Notarize trace`, `3 traces match this view`, `Provider session — Authenticated TLS`.

Avoid generic AI/product language: “unlock,” “elevate,” “seamless,” “powerful,” “reimagine,” “supercharge,” “next-level,” “magic,” “in a world,” “delve,” “leverage,” “robust,” and empty claims of trust or privacy. Avoid made-up section labels, motivational filler, decorative serial numbers, and paragraphs that only repeat visible data.

## Implementation checklist

- Use semantic CSS variables for every reusable Axis color and state in both modes.
- Keep all focus indicators highly visible and preserve keyboard operation for every existing action.
- Preserve all current routes, API calls, loading states, error handling, confirmation behavior, and capture/publication semantics.
- Use actual values in the UI and in comparison artifacts; do not invent a fake dashboard flow when a fixture or live response exists.
- Before handoff, inspect desktop and mobile public flows, authenticated account/authorization flows, and local dashboard fixtures. Verify normal, empty, loading, error, and confirmation states where the product exposes them.
