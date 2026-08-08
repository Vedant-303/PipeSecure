/**
 * PipeSecure — Dependency File Parser (Phase 3)
 *
 * Extracts package names, versions, line numbers, and ecosystem ('PyPI' or 'npm')
 * from data pipeline dependency manifests:
 * - requirements.txt (Python pip)
 * - pyproject.toml (Poetry / Flit / Setuptools)
 * - Pipfile / Pipfile.lock (Pipenv)
 * - package.json (Node.js / npm)
 */

/**
 * Clean package name according to PyPI / npm rules
 */
function normalizePackageName(name) {
  if (!name) return '';
  return name.trim().toLowerCase().replace(/\[.*\]/, ''); // Strip extras like pandas[performance]
}

/**
 * Parse `requirements.txt` style file content.
 * Matches pinned versions (pkg==1.2.3, pkg>=1.2.3, pkg~=1.2.3).
 */
export function parseRequirementsTxt(content, filePath) {
  const dependencies = [];
  const lines = content.split('\n');

  for (let i = 0; i < lines.length; i++) {
    const rawLine = lines[i];
    let line = rawLine.trim();

    // Skip empty lines, comments, and flags (-r, -i, --extra-index-url, etc.)
    if (!line || line.startsWith('#') || line.startsWith('-')) {
      continue;
    }

    // Strip inline comments
    const hashIndex = line.indexOf('#');
    if (hashIndex !== -1) {
      line = line.substring(0, hashIndex).trim();
    }

    // Regex matching pkg==1.2.3, pkg>=1.2.3, pkg~=1.2.3, pkg===1.2.3
    const match = line.match(/^([a-zA-Z0-9_\-\.]+)\s*(?:==|>=|~=|===)\s*([a-zA-Z0-9_\-\.]+)/);
    if (match) {
      dependencies.push({
        name: normalizePackageName(match[1]),
        version: match[2].trim(),
        ecosystem: 'PyPI',
        filePath,
        line: i + 1,
        rawSpec: match[0],
      });
    }
  }

  return dependencies;
}

/**
 * Parse `package.json` file content.
 */
export function parsePackageJson(content, filePath) {
  const dependencies = [];
  try {
    const parsed = JSON.parse(content);
    const sections = ['dependencies', 'devDependencies', 'peerDependencies'];
    const lines = content.split('\n');

    for (const section of sections) {
      if (parsed[section] && typeof parsed[section] === 'object') {
        for (const [pkgName, versionSpec] of Object.entries(parsed[section])) {
          // Extract version string (clean ^, ~, >=)
          const versionMatch = String(versionSpec).match(/(\d+\.\d+\.\d+(?:-[a-zA-Z0-9.]+)?)/);
          const version = versionMatch ? versionMatch[1] : null;

          if (version) {
            // Find line number in raw content for exact UI reporting
            const lineIdx = lines.findIndex(l => l.includes(`"${pkgName}"`));
            dependencies.push({
              name: pkgName,
              version,
              ecosystem: 'npm',
              filePath,
              line: lineIdx >= 0 ? lineIdx + 1 : 1,
              rawSpec: `"${pkgName}": "${versionSpec}"`,
            });
          }
        }
      }
    }
  } catch (err) {
    // Ignore JSON parse errors in malformed files
  }
  return dependencies;
}

/**
 * Parse `pyproject.toml` file content.
 */
export function parsePyprojectToml(content, filePath) {
  const dependencies = [];
  const lines = content.split('\n');
  let inDependenciesSection = false;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i].trim();

    if (line.startsWith('[') && line.endsWith(']')) {
      inDependenciesSection = line.includes('dependencies') || line.includes('tool.poetry.dependencies');
      continue;
    }

    if (inDependenciesSection && line && !line.startsWith('#')) {
      const match = line.match(/^([a-zA-Z0-9_\-\.]+)\s*=\s*['"]\^?~?=?\s*([0-9a-zA-Z_\-\.]+)['"]/);
      if (match && match[1] !== 'python') {
        dependencies.push({
          name: normalizePackageName(match[1]),
          version: match[2].trim(),
          ecosystem: 'PyPI',
          filePath,
          line: i + 1,
          rawSpec: match[0],
        });
      }
    }
  }

  return dependencies;
}

/**
 * Main parser entry point: inspects file path/extension and extracts dependencies.
 * @param {ScanFile} file
 * @returns {Array} List of extracted dependencies
 */
export function extractDependencies(file) {
  const lowerName = file.name.toLowerCase();

  if (lowerName.endsWith('requirements.txt') || lowerName.startsWith('requirements')) {
    return parseRequirementsTxt(file.content, file.path);
  }
  if (lowerName === 'package.json') {
    return parsePackageJson(file.content, file.path);
  }
  if (lowerName === 'pyproject.toml') {
    return parsePyprojectToml(file.content, file.path);
  }
  if (lowerName === 'pipfile' || lowerName.endsWith('.txt')) {
    return parseRequirementsTxt(file.content, file.path);
  }

  return [];
}
