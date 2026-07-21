/* Conventional Commits ruleset for commitlint.
 * .cjs so it loads correctly whether or not the repo's package.json sets "type":"module".
 * Keep in sync with the --extends flag in .github/workflows/lint-pr-title.yml, which
 * hardcodes this ruleset instead of reading this file (it has no checkout step). */
module.exports = {
  extends: ['@commitlint/config-conventional'],
};
