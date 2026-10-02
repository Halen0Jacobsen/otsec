# Contributing to OTSec

Use the [README](README.md), [source map](tooling/README.md), [architecture](Documents/ToolingFoundation.md)
and [security requirements](Requirements/SecurityRequirements.md) before changing behavior.

Keep network/device actions behind explicit capability and environment policy
boundaries. Report normalization must remain offline and bounded. Do not introduce
arbitrary executable paths, shell commands, unreviewed remote binding or automatic
production scans. Proposals currently have no execution path.

Run the documented unittest suite for behavior changes and add focused valid and
adverse cases for parsers, policy and API boundaries. Run node --check after JavaScript
changes and inspect UI changes in a browser. Do not mark hosted CI or scanner
integrations verified based only on local checks.

Maintain the authoritative [brand system](Documents/BrandSystem.md). Keep evidence
rendered as text, not report-supplied HTML. Preserve visible labels, keyboard access,
focus indicators, result-limit disclosure and useful empty/error states.

Update affected API, operations and integration documents along with code. Keep
implemented capabilities and planned controls clearly distinguished. Use synthetic
fixtures; never commit imported production evidence, databases, credentials or raw
secret scan output. The local Zeek checkout is excluded; integrate third-party tools
through adapters rather than copying their source trees into this application.

Bundled fonts retain their SIL Open Font License notices. The WCD logo is a user-
provided brand asset. No blanket application or logo license has been selected;
do not infer redistribution terms from the word open source in tool integrations.
