import path from "node:path";

/** repo-relative, forward-slash path — for SARIF artifact URIs, which must
 *  use "/" even when this runs on Windows. */
export function toRelPosix(repoPath: string, filePath: string): string {
  return path.relative(repoPath, filePath).split(path.sep).join("/");
}
