import ForceGraph3D from '3d-force-graph';

/**
 * Creates a 3D force graph instance
 * This wrapper handles proper typing and instantiation of the ForceGraph3D component
 * and adds missing methods if needed
 */
export const createForceGraph = (container: HTMLElement) => {
  // Work around type issues with ForceGraph3D
  const ForceGraphConstructor = ForceGraph3D as any;
  const graph = ForceGraphConstructor()(container);
  
  // Add centerAt method if it doesn't exist
  if (!graph.centerAt) {
    graph.centerAt = (x: number, y: number, z: number, ms: number) => {
      // Implementation of centerAt that uses lookAt
      if (graph.cameraPosition) {
        const pos = graph.cameraPosition();
        // Only update if we actually have a current position
        if (pos) {
          const distance = Math.sqrt(
            Math.pow(pos.x - x, 2) + 
            Math.pow(pos.y - y, 2) + 
            Math.pow(pos.z - z, 2)
          );
          
          graph.cameraPosition(
            { x, y, z: z + distance }, // New position - back away from the target
            { x, y, z },  // Look-at position (the target)
            ms  // Animation duration
          );
        }
      }
      
      return graph; // Chain
    };
  }
  
  return graph;
};