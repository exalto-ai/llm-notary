# Provider icon assets

The hosted website and independently publishable local dashboard use matching
presentation-only provider mappings. Their assets are deliberately copied into
each workspace so the public runtime has no dependency on the hosted site. The
mappings read the existing provider field; they never infer a provider from a
model name, hostname, or namespaced OpenRouter model slug. Unknown and missing
values use the neutral Notary fallback mark while retaining the supplied
provider text when one is present.

All four provider assets are bundled into both built applications. They are
rendered as decorative, monochrome masks beside visible provider text so the
same files remain legible in light and dark themes. Neither UI loads brand
assets from third-party hosts.

## Sources and usage terms

| Provider | Hosted asset | Public-runtime copy | Source and terms checked |
| --- | --- | --- | --- |
| OpenAI | `platform/web/src/assets/providers/openai.svg` | `runtime/apps/admin-dashboard/src/assets/providers/openai.svg` | Geometry from OpenAI's official [Blossom asset](https://images.ctfassets.net/kftzwdyauwt9/3hUGLn3ypllZ0oa01qOYVq/28e8188e6f11b84c3e876569d492734f/Blossom_Light.svg) and used under the [OpenAI design guidelines and Marks usage terms](https://openai.com/brand/). The mark identifies an OpenAI-authenticated provider record, is secondary to Notary branding, and does not imply endorsement. |
| Anthropic | `platform/web/src/assets/providers/anthropic.svg` | `runtime/apps/admin-dashboard/src/assets/providers/anthropic.svg` | Anthropic symbol from the official [Anthropic press kit](https://www.anthropic.com/press-kit). Anthropic does not publish a separate license in the kit; the mark is used only as a small adjacent identifier and remains an Anthropic trademark. |
| DeepSeek | `platform/web/src/assets/providers/deepseek.svg` | `runtime/apps/admin-dashboard/src/assets/providers/deepseek.svg` | Official `ICON.svg` and [brand asset usage guidelines](https://github.com/deepseek-ai/awesome-deepseek-integration/tree/main/docs/_logo%20svg) from DeepSeek's integration repository, which is distributed under [CC0-1.0](https://github.com/deepseek-ai/awesome-deepseek-integration/blob/main/LICENSE). The guidelines permit accurate use by developers integrating DeepSeek APIs and prohibit false partnership claims. CC0 does not waive trademark rights. |
| OpenRouter | `platform/web/src/assets/providers/openrouter.svg` | `runtime/apps/admin-dashboard/src/assets/providers/openrouter.svg` | Current glyph from OpenRouter's official [v2 brand asset](https://openrouter.ai/brand/v2/openrouter-glyph-light.svg), cross-checked against its [2026 brand refresh](https://openrouter.ai/blog/announcements/brand-refresh/) and official [documentation repository](https://github.com/OpenRouterTeam/docs/blob/main/assets/favicon-v2.svg). No standalone asset license is published; OpenRouter retains its rights under its [Terms of Service](https://openrouter.ai/terms). The glyph identifies only an OpenRouter-authenticated record, even when model metadata names an upstream vendor. |

Provider names, logos, and trademarks belong to their respective owners. The
assets are not part of Notary's own brand and must not be reused to imply a
provider partnership or endorsement.
