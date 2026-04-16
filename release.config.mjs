export default {
  repositoryUrl: "https://github.com/nowsecure/nowsecure-network-broker",
  branches: [
    { name: "release" },
    { name: "main", prerelease: "rc" },
  ],
  plugins: [
    [
      "@semantic-release/commit-analyzer",
      {
        preset: "conventionalcommits",
        releaseRules: [
          { breaking: true, release: "minor" },
          { type: "feat", release: "minor" },
          { revert: true, release: "patch" },
          { type: "build", release: "patch" },
          { type: "chore", release: "patch" },
          { type: "docs", release: "patch" },
          { type: "fix", release: "patch" },
          { type: "perf", release: "patch" },
          { type: "test", release: "patch" },
          { type: "refactor", release: "patch" },
        ],
      },
    ],
    "@semantic-release/release-notes-generator",
    "@semantic-release/github",
  ],
};
