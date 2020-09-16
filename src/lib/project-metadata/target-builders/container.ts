import { DepTree } from '../../types';
import { ContainerTarget } from '../types';
import { ScannedProject } from '@snyk/cli-interface/legacy/common';
import { ScanResult } from '../../ecosystems';

export async function getInfo(
  isFromContainer: boolean,
  scannedProject: ScannedProject | ScanResult,
  packageInfo?: DepTree,
): Promise<ContainerTarget | null> {
  // safety check
  if (!isFromContainer) {
    return null;
  }

  const imageNameOnProjectMeta =
    scannedProject.meta && scannedProject.meta.imageName;
  return {
    image:
      imageNameOnProjectMeta ||
      (packageInfo as any)?.image ||
      packageInfo?.name,
  };
}
