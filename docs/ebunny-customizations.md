# Existing eBunny bot customizations

This branch preserves the existing server customizations before development of
separate BS/WL traffic accounting. It does not implement traffic splitting,
create extra Remnawave accounts, or change database models or migrations.

## Import source

- Uploaded archive: `ebunny-bot-local-changes-o8k7Lk.tar.gz`.
- Server base recorded in the archive:
  `5bda3c56f0afd9f4813e9c6fa48934948b05ebae`.
- Fork base used for this import:
  `12c92f8e895638ab8d26b6af2ff77ac8ea91b9fd`.
- The archived `local-changes.patch` applied to the fork base without conflicts.

## Preserved behavior

- `app/keyboards/inline.py`: premium emoji on the ordinary main-menu keyboard,
  a green connect button, and a red admin button. The existing button actions,
  labels, visibility rules, and row layout are retained. Ruff formatting is the
  only change to the imported patch's layout.
- `vpn_logo.png`: the exact uploaded server logo (2,045,103 bytes).
- `docker-compose.yml`: the existing `user: root` override for the bot service.
  No other Compose settings were imported or changed.
- `locales/{en,fa,ru,ua,zh}.json`: nine server-specific payment amount messages
  per language, stored as overrides for the existing locale loader. Full older
  runtime dictionaries were not copied: their 24 missing current keys continue
  to come from the bundled defaults in `app/localization/locales`.

Server backup files, `inline.py.before-*`, archive metadata, environment files,
database dumps, generated logs, and credentials are not part of this import.

## Validation

Use Python 3.14 and the checked-in lockfile:

```sh
uv sync --frozen --group dev
uv run ruff check app/keyboards/inline.py
uv run ruff format --check app/keyboards/inline.py
uv run pytest -q tests/test_legacy_subscription_keyboard.py tests/test_locale_integrity.py tests/test_menu_subscription_status.py tests/test_logo_resize.py tests/test_logo_path_validation.py tests/test_logo_file_id_cache_invalidation.py
git diff --check
```

Additional local smoke checks compare ordinary/admin menu button actions and
layout with the fork base, check the imported emoji and button styles, verify
the PNG image, and verify locale fallback. These checks do not call Telegram,
payment providers, or a production Remnawave panel.

This import is source preservation, not a production deployment. Updating the
running bot requires a separate deployment step using the server's actual
configuration and a fresh backup.
