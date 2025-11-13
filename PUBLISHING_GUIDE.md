# Publishing Guide for SifreDB

This guide will help you publish the SifreDB crates to crates.io.

## Prerequisites

### 1. Create a crates.io Account

1. Go to https://crates.io/
2. Sign in with your GitHub account
3. Verify your email address

### 2. Get API Token

1. Go to https://crates.io/settings/tokens
2. Click "New Token"
3. Give it a name (e.g., "SifreDB Publishing")
4. Select scopes (typically "publish-update" is sufficient)
5. Click "Generate" and copy the token
6. Save it securely - you won't be able to see it again!

### 3. Login to Cargo

Run this command and paste your API token when prompted:

```powershell
cargo login
```

Or directly:

```powershell
cargo login <your-token>
```

This saves your token in `~/.cargo/credentials.toml`

## Pre-Publishing Checklist

- [x] All tests pass (`cargo test --workspace --exclude sifredb-kms-aws`)
- [x] README.md is up to date and in English
- [x] LICENSE files exist (Apache-2.0 and MIT)
- [x] All Cargo.toml files have proper metadata
- [x] Version dependencies are specified
- [x] `cargo publish --dry-run` succeeds

## Publishing Order

⚠️ **IMPORTANT**: Publish crates in this order due to dependencies:

### 1. Publish Core Library First

```powershell
cd sifredb
cargo publish
cd ..
```

Wait a few minutes for the crate to be available on crates.io before proceeding.

### 2. Publish Derive Macros

```powershell
cd sifredb-derive
cargo publish
cd ..
```

### 3. Publish Key Providers

```powershell
cd sifredb-key-file
cargo publish
cd ..
```

### 4. Publish CLI Tool

```powershell
cd sifredb-cli
cargo publish
cd ..
```

### 5. Publish AWS KMS Provider (Optional)

⚠️ **Note**: This requires cmake and NASM to be installed on your system.

If you want to publish the AWS KMS provider:

```powershell
# Install cmake and NASM first
# Then:
cd sifredb-kms-aws
cargo publish
cd ..
```

## After Publishing

### 1. Tag the Release

```powershell
git tag -a v0.1.0 -m "Release v0.1.0"
git push origin v0.1.0
```

### 2. Create GitHub Release

1. Go to your repository on GitHub
2. Click "Releases" → "Create a new release"
3. Select the tag you just created
4. Add release notes describing:
   - New features
   - Bug fixes
   - Breaking changes
   - Migration guide (if applicable)

### 3. Update Documentation

- The documentation will be automatically built at https://docs.rs/sifredb
- Verify it looks correct after a few minutes

### 4. Announce the Release

Consider announcing on:
- Rust subreddit (r/rust)
- This Week in Rust
- Your blog or social media
- Relevant Discord/Slack channels

## Updating a Published Crate

To publish a new version:

1. Update version in `Cargo.toml` (workspace level)
2. Update CHANGELOG.md with changes
3. Run tests: `cargo test --workspace --exclude sifredb-kms-aws`
4. Commit changes: `git commit -am "Bump version to x.y.z"`
5. Publish in the same order as above
6. Tag and create GitHub release

## Troubleshooting

### "crate already exists"

You cannot publish the same version twice. Bump the version number.

### "no matching package found"

The dependency crate hasn't been published yet or isn't available on crates.io. Publish dependencies first.

### "uncommitted changes in working directory"

Either commit your changes or use `--allow-dirty` flag (not recommended for production).

### "failed to verify package"

Run `cargo package --list` to see what will be included. Check for missing files or large files that shouldn't be published.

## Yanking a Version

If you need to yank a broken version:

```powershell
cargo yank --vers 0.1.0
```

To un-yank:

```powershell
cargo yank --vers 0.1.0 --undo
```

## Best Practices

1. **Always test before publishing**: Run full test suite
2. **Use semantic versioning**: Follow [SemVer](https://semver.org/)
3. **Keep CHANGELOG**: Document all changes
4. **Write good commit messages**: They become release notes
5. **Don't rush**: Take time to review everything
6. **Communicate breaking changes**: Give users time to migrate

## Current Status

✅ Ready to publish:
- sifredb (core library)
- sifredb-derive (macros)
- sifredb-key-file (file provider)
- sifredb-cli (CLI tool)

⚠️ Requires setup:
- sifredb-kms-aws (needs cmake and NASM)

## Questions?

- Check [The Cargo Book](https://doc.rust-lang.org/cargo/)
- Ask on [Rust Users Forum](https://users.rust-lang.org/)
- Join [Rust Discord](https://discord.gg/rust-lang)
