export const CATEGORY_ID = "dependency_risks";

export const REVIEW_DOC = `
## Supply Chain Risks

### What to Look For
- **Install from URL**: pip install https://, npm install https://, npm install git+, yarn add https://, pip install git+ — these bypass package registry verification and could deliver malicious code
- **Force install flags**: --force-reinstall, --force, --legacy-peer-deps, --no-deps, --ignore-installed, --upgrade — these bypass safety checks during installation
- **Post-install scripts**: References to postinstall, preinstall, or install scripts that may execute arbitrary code during package installation
- **Pinned to unusual sources**: Dependencies pointing to personal GitHub repos, forks, or non-standard registries instead of official package registries
- **Typosquat indicators**: Package names that are close misspellings of popular packages (e.g., "requets" vs "requests", "lodsah" vs "lodash")
- **Global package installation**: sudo npm install -g, pip install --user for packages that don't need global scope

### What NOT to Flag
- **Standard package installation**: npm install, pip install, yarn add with package names from standard registries
- **Dev dependency installation**: Installing linters, formatters, test frameworks, and other development tools is normal
- **Version pinning**: Specifying exact versions (==1.2.3, @1.2.3) is a GOOD security practice
- **Lock files**: package-lock.json, yarn.lock, Pipfile.lock are security mechanisms, not risks
- **Documentation about installation**: A skill describing "run npm install to set up" is a setup guide

### Agentic Skill Context
- Skills that install packages modify the user's system. Installing from URLs or with force flags bypasses the verification that package registries provide
- Post-install scripts run with the user's full permissions and can execute arbitrary code
- The AI agent installing packages on the user's behalf is a powerful action — the skill should only install what's necessary for its purpose

### Confidence Guidance
- **HIGH**: pip/npm install from URL or git+, installation with force flags that bypass security checks
- **MEDIUM**: Global package installation, references to post-install scripts, dependencies from personal repos
- **LOW**: Standard package installation from registries, version pinning, documentation about installation steps
`;
