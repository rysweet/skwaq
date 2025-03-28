## Investigation Visualization Screenshot

Below is a screenshot of the Sources and Sinks visualization with funnel-identified nodes (would need to be added manually):

```
+------------------------------------------------+
|                                |               |
|                                | Sources and   |
|         [Investigation]        | Sinks Analysis|
|             |                  |               |
|             +---------------+  | [Zoom In]     |
|             |               |  | [Zoom Out]    |
|             v               v  | [Reset]       |
|     +--------+         +--------+              |
|     |        |         |        |              |
|     | Source |-------->| Flow   |---+          |
|     | ******|         | *******|   |          |
|     +--------+         +--------+   |          |
|        |                            |          |
|        |                            v          |
|        |                        +--------+     |
|        |                        |        |     |
|        |                        | Sink   |     |
|        |                        | ******|     |
|        |                        +--------+     |
|        |                            |          |
|        v                            v          |
|     +--------+                +--------+       |
|     |        |                |        |       |
|     | File 1 |                | File 2 |       |
|     |        |                |        |       |
|     +--------+                +--------+       |
|                                                |
+------------------------------------------------+

* Gold border indicates funnel-identified nodes
```

The visualization allows users to:

1. See the relationship between Sources, Sinks, and DataFlowPaths
2. Easily identify funnel-identified nodes with gold borders and animations
3. Filter different node types to focus on specific aspects
4. Get detailed information by clicking on nodes
5. Zoom and pan for better exploration of complex graphs