# Data-flow diagram

Each review draws a data-flow diagram (DFD) of the work item's architecture: who and what talks to whom, across which trust
boundaries, and where the threats sit.

## Where it comes from

- **Sketch.** Threatline Engine's quarantined injection check extracts an architecture sketch (components, data stores,
  external services, trust boundaries, flows) and checkpoints it as the review's `extract` stage. Rovo agent mode has no
  such stage, so the diagram uses the union of the agent runs' sketches, which carry no flows. Any sketch string that reads
  like an instruction to an AI (the injection scanner) is dropped.
- **Threats.** Each threat's `component` is matched to an element by name: case, punctuation and simple plurals are
  ignored; an exact match wins, then whole-word containment, then a token overlap of at least half. A component that
  matches nothing becomes its own element, marked "named only by a threat".
- **Layout.** `layoutDiagram` (`packages/core/src/diagram.ts`) is pure and deterministic: no I/O, no model, and the same
  input always gives the same output. It uses columns external entity → process → data store, with one horizontal lane per
  trust boundary. An element belongs to the first boundary whose text names it. A boundary written as a crossing
  ("Internet → API", "Stripe to webhook endpoint") holds only the elements on its last side. When no named boundary matches
  any element, an implied "System" boundary encloses the processes and stores. Elements never overlap, each boundary box
  holds only its own elements, and edge captions are placed where they do not cover a box or another caption. The layout
  handles 30 of everything, the sketch schema's maximum.

Each element carries its threat count, its open count (threats that are not dismissed and whose requirements are not all
closed) and its highest open severity.

## Where it shows

| Surface | What |
| --- | --- |
| Issue panel, **Diagram** tab | Inline SVG built from React elements, with all text escaped by React. Rounded boxes are external entities, rectangles are processes, open-ended boxes are data stores, and dashed boxes are trust boundaries. Elements are coloured by their highest open severity using Atlaskit accent tokens (light and dark), and the severity is also written in words. The drawing is one `role="img"` with a one-sentence summary. Each element is a real button laid over the drawing: clicking it or giving it keyboard focus filters the threat list below to that element, and Escape or **Show all threats** clears the filter. **Show the diagram as tables** lists the elements, flows, boundaries and threats as text. |
| Confluence threat-model page | A **Data-flow diagram** section with three tables: Elements, Data flows (from, to, data, crosses a trust boundary?) and Trust boundaries. Storage format cannot carry inline SVG safely, and an image attachment would need a Confluence file-write scope that Threatline does not request. |
| `get-review` (MCP and Rovo) | `dataFlowDiagram`: compact text listing the elements (with each element's boundary, threats and T-n refs), the numbered flows and the boundaries, capped at 6,000 characters. |

## Who sees what

The sketch is extracted from every source of the review, so it is shown only to readers who can open every source:

- **Panel and `get-review`:** the viewer must be able to open every fact of the review, the same rule as the discarded
  threats.
- **Confluence page:** every fact must be the work item's own or the parent design page's.

Anyone else gets a diagram built only from the threats they can see, plus a note that parts of the architecture were left
out. Threats are always viewer-scoped first.

## Changing the layout

The panel's local preview (`?state=ready`) uses `apps/core/ui/src/diagram-fixture.ts`. That file is generated from a PAY-6
sketch and the panel's fixture threats by `apps/core/test/services/diagram.test.ts`. After changing the layout or those
fixtures, run `pnpm vitest run apps/core/test/services/diagram.test.ts -u`.
