#!/bin/sh

set -eu

usage() {
  echo "Usage: $0 <version-or-tag> [changelog-file]" >&2
  exit 2
}

[ "$#" -ge 1 ] && [ "$#" -le 2 ] || usage

tag="$1"
version="${tag#v}"
script_dir=$(CDPATH= cd "$(dirname "$0")" && pwd)
changelog_file="${2:-${script_dir}/../CHANGELOG.md}"

if [ ! -f "$changelog_file" ]; then
  echo "Changelog not found: $changelog_file" >&2
  exit 1
fi

release_block=$(
  awk -v version="$version" '
    $0 == "## [" version "]" || index($0, "## [" version "] - ") == 1 {
      found = 1
      next
    }
    found && /^## \[/ { exit }
    found { print }
    END {
      if (!found) {
        exit 1
      }
    }
  ' "$changelog_file"
) || {
  echo "Version $version was not found in $changelog_file" >&2
  exit 1
}

extract_section() {
  target="$1"
  printf '%s\n' "$release_block" | awk -v target="$target" '
    /^### / {
      active = substr($0, 5) == target
      started = 0
      next
    }
    active {
      if (!started && $0 == "") {
        next
      }
      print
      started = 1
    }
  '
}

extract_other_sections() {
  printf '%s\n' "$release_block" | awk '
    /^### / {
      name = substr($0, 5)
      active = name != "新增" && name != "修复"
      if (active) {
        print $0
      }
      next
    }
    active { print }
  '
}

added=$(extract_section "新增")
fixed=$(extract_section "修复")
other=$(extract_other_sections)

printf '# Refract %s\n\n' "$tag"
printf '## 新增功能\n\n'
if [ -n "$added" ]; then
  printf '%s\n' "$added"
else
  printf '%s\n' '- 本版本没有单独列出的新增功能。'
fi

printf '\n## 修复内容\n\n'
if [ -n "$fixed" ]; then
  printf '%s\n' "$fixed"
else
  printf '%s\n' '- 本版本没有单独列出的修复项。'
fi

if [ -n "$other" ]; then
  printf '\n## 其他变更\n\n%s\n' "$other"
fi

cat <<'EOF'

## 一键升级

```bash
curl -fsSL https://raw.githubusercontent.com/T-Matrix/Refract/main/scripts/install.sh | sudo sh
```

升级脚本会自动识别 Docker Compose 或原生 systemd 部署，并保留现有配置、数据库和证书。升级前会校验发布文件，原生部署升级失败时会自动回滚。
EOF
