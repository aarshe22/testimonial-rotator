# Testimonial Rotator

WordPress plugin for managing testimonials and displaying them in a rotator or list. Current version: **3.0.4**.

## Security fixes in 3.0.4

Version 3.0.3 allowed some authenticated users (including Contributors, who do not have `unfiltered_html`) to persist HTML and JavaScript. When an Administrator later viewed wp-admin or a published rotator, that script could run in their session.

### 1. Stored XSS in Author Information (`_cite`)

The cite field is a TinyMCE editor on the testimonial CPT. Contributors can create testimonials (`capability_type` is `post`). 3.0.3 saved cite with `wp_kses( ..., wp_kses_allowed_html() )` (no context, no capability check) and then printed it raw:

- Frontend templates: `echo wpautop( $cite )`
- Admin list column **Author Information**: `echo get_post_meta( ..., '_cite' )`

That admin column is the privilege-escalation path: a Contributor submits a payload, an Editor or Admin opens **All Testimonials**, and the script runs in wp-admin.

**Fix:** `testimonial_rotator_sanitize_cite()` allow-lists basic formatting (bold, italic, `https` links) and strips scripts, event handlers, and `javascript:` URLs. It runs on save and again on output (frontend and admin).

### 2. Stored XSS via `title_heading` and related attributes

`title_heading` is interpolated as a raw HTML tag:

```php
echo "<{$title_heading} class=\"testimonial_rotator_slide_title\">";
```

3.0.3 used only `strip_tags()`, which does not stop payloads with no angle brackets, for example `img src=x onerror=alert(1)` or `h2 onclick=alert(1)`. Contributors can also pass `title_heading`, `extra_classes`, `fx`, and `template` in a shortcode.

**Fix:**

- Headings must be one of `h1`–`h6`, `p`, `div`, `span`; anything else becomes `h2`
- `extra_classes` cannot break out of a `class=""` attribute
- `fx` and `template` are allow-listed; `../` template paths are rejected
- The same sanitizers run on rotator save, widget update, shortcode atts, and render

Helpers live in `includes/sanitization.php`.

## Tests

PHPUnit records the 3.0.3 failures and asserts the patched helpers block the same payloads. No WordPress database is required.

```bash
composer install
vendor/bin/phpunit --testdox
vendor/bin/phpunit --group before --testdox
vendor/bin/phpunit --group after --testdox
```

`--group before` documents that the old sanitizers were unsafe. `--group after` must stay green; if it fails, XSS was reintroduced.

See `PLAN.md` for the full mitigation notes.
