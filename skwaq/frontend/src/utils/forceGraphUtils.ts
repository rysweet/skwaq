import ForceGraph3D from '3d-force-graph';

/**
 * Creates a 3D force graph instance
 * This wrapper handles proper typing and instantiation of the ForceGraph3D component
 */
export const createForceGraph = (container: HTMLElement) => {
  // Work around type issues with ForceGraph3D
  const ForceGraphConstructor = ForceGraph3D as any;
  return ForceGraphConstructor()(container);
};