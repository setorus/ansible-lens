export default {
  extends: ["@commitlint/config-conventional"],
  // Default GitHub merge commits ("Merge pull request #N ...") are ignored by commitlint already.
  rules: { "body-max-line-length": [0] },
};
