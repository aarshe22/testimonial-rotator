# Security Mitigation Plan — Testimonial Rotator 3.0.3

Two authenticated stored XSS issues let users **without** the `unfiltered_html` capability (Contributors, Authors, and in Multisite even site Admins) inject HTML/JavaScript. When an Administrator later views wp-admin or a published rotator, that script runs in their session and can create users, change settings, or take over the site.

The `testimonial` CPT uses `capability_type => 'post'`, so Contributors can create testimonials. Shortcodes in their post content are also executed. Neither path currently enforces WordPress’s `unfiltered_html` contract.

---

## Vulnerability 1 — Stored XSS in Author Information (`_cite`)

**Public mapping:** CVE-2020-26672 (`cite` on `post.php`). 3.0.3 added a `wp_kses()` call; the remaining 2021 “Authenticated Stored XSS ≤ 3.0.3” report shows that fix is incomplete.

### What’s wrong

1. **Save is not capability-aware.** `testimonial_rotator_save_testimonial_meta()` stores `$_POST['cite']` with:

   ```php
   wp_kses( $_POST['cite'], wp_kses_allowed_html() )
   ```

   `wp_kses_allowed_html()` with no context is the wrong API. It does not apply the same rules WordPress uses for post content, and it never checks `unfiltered_html`. Contributors get an HTML editor (`wp_editor()`) for this field even though they are not allowed to post unfiltered HTML.

2. **Output is never escaped.** Every theme template prints the stored value as HTML:

   ```php
   echo wpautop( $cite );
   ```

   The admin Testimonials list does the same:

   ```php
   echo get_post_meta( $post_id, '_cite', true );
   ```

   That last line is the privilege-escalation path: a Contributor submits HTML, an Editor/Admin opens **All Testimonials**, and the payload runs in wp-admin.

3. **The save callback is unguarded.** No nonce, no `current_user_can( 'edit_post', $post_id )`, no autosave/revision bail-out. Anyone who can trigger `save_post_testimonial` can write `_cite`.

### Where

| Area | File | Notes |
| --- | --- | --- |
| Save | `admin/metaboxes-testimonial.php` → `testimonial_rotator_save_testimonial_meta()` | Weak kses, no auth/nonce |
| Editor | same file → `testimonial_rotator_metabox_select()` | TinyMCE for all roles |
| Frontend | `templates/**/loop-testimonial.php`, `templates/**/single-testimonial.php` | `echo wpautop($cite)` |
| Admin list | `admin/admin-functions.php` → `testimonial_rotator_add_columns()` | Raw `_cite` in `author_info` |

### Mitigation

**On save (`testimonial_rotator_save_testimonial_meta`):**

- Return early on autosave, revisions, and if `! current_user_can( 'edit_post', $post_id )`.
- Verify a dedicated metabox nonce (`wp_nonce_field` in the metabox, `wp_verify_nonce` on save).
- Sanitize `_cite` the same way core sanitizes post content:
  - If `current_user_can( 'unfiltered_html' )`, allow the submitted HTML (still run `wp_kses_post()` only if you want a hard allow-list; otherwise store as submitted).
  - Otherwise run `wp_kses_post()` **or** a tight allow-list (bold, italic, link with `http`/`https` only — matching the TinyMCE button set).
- Do **not** call `wp_kses_allowed_html()` with an empty context.
- Cast `_rating` with `absint()` and clamp 0–5. Cast each `_rotator_id` with `absint()` and confirm each ID is a `testimonial_rotator` post.

**On output:**

- Frontend: `echo wp_kses_post( wpautop( $cite ) );` (or `wp_kses()` with the same tight allow-list used on save).
- Admin column: `echo wp_kses_post( get_post_meta( ... ) );` — never echo raw meta in wp-admin.
- Prefer a small helper, e.g. `testimonial_rotator_get_cite( $post_id )`, so every template uses one escaped getter.

**Editor:** keep TinyMCE, but the save-time kses is what actually enforces the capability. Optionally hide the visual editor for users without `unfiltered_html` and use a plain textarea plus `esc_textarea()`.

---

## Vulnerability 2 — Stored XSS via HTML tag/attribute injection (`title_heading` and related values)

Contributors do not need rotator-edit access. They can put a shortcode in a post they are allowed to create:

```
[testimonial_rotator id="123" title_heading='img src=x onerror=alert(1)']
[testimonial_rotator extra_classes='" onmouseover="alert(1)']
```

Those values are interpolated into markup with no escaping.

### What’s wrong

**`title_heading` is used as a raw HTML tag name:**

```php
echo "<{$title_heading} class=\"testimonial_rotator_slide_title\">";
```

Save uses only `strip_tags()`. That does not stop:

- `img src=x onerror=alert(1)` → `<img src=x onerror=alert(1) class="...">`
- `h2 onclick=alert(1)` → `<h2 onclick=alert(1) class="...">`

The metabox `maxlength="12"` is client-side only and is not enforced on save, widget update, or shortcode atts.

**Other values are printed inside HTML attributes with no `esc_attr()`:**

In `testimonial_rotator()` (`testimonial-rotator.php`): `extra_classes`, `fx`, `div_selector`, `auto_height`, `template_name`, `pause_on_hover`, and related `data-cycletwo-*` attributes. A quote in any of these breaks out of the attribute.

**Rotator meta save is the same class of bug** (`testimonial_rotator_save_rotator_meta()`): `strip_tags()` on `title_heading`, `template`, `fx`, `img_size`, `itemreviewed`; no nonce; no capability check. The rotator CPT also uses `capability_type => 'post'`, and the “Who Sees Rotator Menu?” setting only hides the menu. A Contributor who knows `post-new.php?post_type=testimonial_rotator` can still create rotators and persist XSS in rotator meta.

**Widget `update()`** copies `title_heading` and other fields through unsanitized.

### Where

| Area | File | Notes |
| --- | --- | --- |
| Tag output | all `templates/**/*.php` | `"<{$title_heading} ...>"` |
| Shortcode / rotator render | `testimonial-rotator.php` → `testimonial_rotator()` | Unescaped atts in class/data attributes; `$itemreviewed` in HTML |
| Rotator save | `admin/metaboxes-rotator.php` → `testimonial_rotator_save_rotator_meta()` | `strip_tags` only; no nonce/caps |
| Widget | `widget.php` → `update()` | Pass-through of attacker-controlled strings |
| CPT caps | `testimonial-rotator.php` → `testimonial_rotator_init()` | Rotator is `capability_type => 'post'` |

### Mitigation

**Treat `title_heading` as a tag-name allow-list, not as free text.**

```php
function testimonial_rotator_sanitize_heading( $tag ) {
    $tag = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $tag ) );
    $allowed = array( 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span' );
    return in_array( $tag, $allowed, true ) ? $tag : 'h2';
}
```

Use this helper on rotator save, widget `update()`, and when reading shortcode atts. In templates, still print a sanitized variable (never raw user input as a tag name).

**Escape every attribute and text node at the echo site:**

- `esc_attr()` for `class`, `id`, and all `data-cycletwo-*` values (`fx`, `timeout`, `speed`, `div_selector`, `auto_height`, `template_name`, `extra_classes`).
- `esc_html()` for `$itemreviewed` and any other text dropped into HTML.
- `sanitize_html_class()` for class fragments (`extra_classes`, `template_name`).
- `sanitize_key()` / allow-list for `fx` (`testimonial_rotator_base_transitions()`), `format` (`rotator`\|`list`), `img_size` (from `get_intermediate_image_sizes()`), `template` (keys of `testimonial_rotator_available_themes()`).

**Template path:** `$template_name` is concatenated into filesystem paths. After the allow-list check, reject `..`, `/`, and `\` so a shortcode cannot traverse out of `templates/`.

**Rotator save:** same nonce + `current_user_can( 'edit_post', $post_id )` + autosave/revision guards as Vulnerability 1. Integers (`timeout`, `speed`, `limit`) via `absint()`. Checkboxes as `1`/`0`.

**Widget `update()`:** run the same sanitizers; do not copy `$new_instance` fields through raw.

**Access control (needed so Contributors cannot persist rotator XSS even if shortcodes are locked down):**

- Register `testimonial_rotator` with custom capabilities (`capability_type` + `map_meta_cap`), **or** `remove_cap` for `edit_posts` on that type for roles that are not in `testimonial-rotator-creator-role` / Administrators.
- The settings checkboxes must match real `register_post_type` capabilities, not only `add_submenu_page()`.
- Drop `'custom-fields'` from `supports` on both CPTs unless you register each meta key with `auth_callback` and `sanitize_callback` via `register_post_meta()`. Unregistered custom fields let Contributors write arbitrary meta that bypasses the metabox sanitizers.

---

## Shared hardening (both issues)

These are not extra product features; without them the XSS fixes can be bypassed.

1. **Nonce on both metaboxes.** `wp_nonce_field( 'testimonial_rotator_save', 'testimonial_rotator_nonce' )` and verify before any `update_post_meta()`.
2. **Capability + context checks** in both save callbacks: `DOING_AUTOSAVE`, `wp_is_post_revision()`, `current_user_can( 'edit_post', $post_id )`.
3. **Settings sanitization.** `register_setting()` for `testimonial-rotator-custom-css`, `testimonial-rotator-creator-role`, and `testimonial-rotator-archive-slug` currently has no real sanitize callback. CSS should be `wp_strip_all_tags()` (or a CSS sanitizer); roles should be intersected with `get_editable_roles()`; slug should be `sanitize_title()`.
4. **Admin list / rotator title links** in `testimonial_rotator_add_columns()` and `testimonial_rotator_testimonial_count_meta()`: `esc_url()`, `esc_html()`, `esc_attr()` on titles and query args.
5. **Version bump** to `3.0.4` in `testimonial-rotator.php` and `readme.txt`, with a changelog line that these two XSS issues are fixed.

---

## Implementation order

1. Add sanitizer helpers (heading allow-list, cite kses, theme/fx/img_size allow-lists) in one place, e.g. a small `includes/sanitization.php` required from the main plugin file (admin and front).
2. Fix both save callbacks (nonce, caps, sanitizers) — this stops persistence.
3. Escape all template and `testimonial_rotator()` echo sites — this stops execution of any already-stored payloads.
4. Sanitize widget `update()` and shortcode atts at the start of `testimonial_rotator()`.
5. Tighten rotator CPT capabilities and remove unregistered `custom-fields` support.
6. Escape admin columns and add setting sanitizers.
7. Bump version and document in `readme.txt`.

Do not rely on “sanitize on save only.” Stored XSS in this plugin exists because output is trusted. Input sanitization **and** output escaping are both required.

---

## Test plan (after implementation)

Use a Contributor account that does **not** have `unfiltered_html` (default on single-site and always on Multisite).

**Cite (Vuln 1)**

- Create a testimonial with Author Information containing `<script>alert(1)</script>`, `<img src=x onerror=alert(1)>`, and `<a href="javascript:alert(1)">x</a>`.
- Confirm the script/event handlers are stripped in the database and never run on the front or on **All Testimonials**.
- Confirm basic markup you still want (e.g. `<strong>`, `<a href="https://example.com">`) survives for users with `unfiltered_html` if that is the intended product behavior.
- Confirm a Contributor cannot save cite via a crafted POST without a valid nonce.

**Heading / shortcode (Vuln 2)**

- Publish a post as Contributor: `[testimonial_rotator id="{valid}" title_heading='img src=x onerror=alert(1)']` — title must render as `<h2>` (fallback), no `onerror`.
- `[testimonial_rotator extra_classes='" onmouseover="alert(1)']` — class attribute must not break out.
- `[testimonial_rotator template="../../../etc"]` — template must fall back to `default`; no path traversal.
- As Contributor, open `post-new.php?post_type=testimonial_rotator` — must be denied unless the role is explicitly allowed in settings.
- Widget: set Element for Title Field to `h2 onclick=alert(1)` — must store `h2` or fallback.

**Regression**

- Default rotator still rotates; list format, stars, cite, images, and microdata still render.
- Allowed headings `h1`–`h6` still work when set by an Administrator.
- Existing rotators with empty `_title_heading` still default to `h2`.

---

## Out of scope for this fix (follow-ups)

- Theme updater `unserialize()` of a remote body (`testimonial-rotator-theme-updater.php`) is unsafe if that file is used again; prefer `json_decode`.
- Custom CSS in settings is admin-only; still sanitize so a compromised admin session cannot inject `</style><script>`.
- No automated PHPUnit coverage exists; adding tests for the sanitizer helpers would lock the allow-lists in place.
