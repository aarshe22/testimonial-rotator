<?php

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) ) {
	exit;
}

/**
 * Allowed HTML for the Author Information (cite) field.
 * Matches the TinyMCE button set: bold, italic, link.
 *
 * @return array
 */
function testimonial_rotator_cite_allowed_html() {
	return array(
		'a'      => array(
			'href'  => true,
			'title' => true,
		),
		'strong' => array(),
		'b'      => array(),
		'em'     => array(),
		'i'      => array(),
		'br'     => array(),
		'p'      => array(),
		'span'   => array(),
	);
}

/**
 * Sanitize Author Information on save and on output.
 * Strips script/event-handler XSS while keeping basic formatting.
 *
 * @param mixed $cite Raw cite HTML.
 * @return string
 */
function testimonial_rotator_sanitize_cite( $cite ) {
	$cite = testimonial_rotator_kses_cite_fallback( (string) $cite );

	if ( function_exists( 'wp_kses' ) ) {
		$cite = wp_kses( $cite, testimonial_rotator_cite_allowed_html() );
	}

	return $cite;
}

/**
 * Extra cite sanitization before wp_kses, as a defense-in-depth pass.
 *
 * @param string $html
 * @return string
 */
function testimonial_rotator_kses_cite_fallback( $html ) {
	$html = str_replace( "\0", '', (string) $html );

	$html = preg_replace( '#<\s*(script|style|iframe|object|embed|form|svg|math)[^>]*>.*?<\s*/\s*\1\s*>#is', '', $html );
	$html = preg_replace( '#<\s*(script|style|iframe|object|embed|form|svg|math)[^>]*/?\s*>#is', '', $html );
	$html = preg_replace( '/\son[a-z]+\s*=\s*("[^"]*"|\'[^\']*\'|[^\s>]+)/i', '', $html );
	$html = preg_replace_callback(
		'/\s(href|src)\s*=\s*(["\']?)([^"\'>\s]*)/i',
		function ( $m ) {
			if ( preg_match( '/^\s*(javascript|data|vbscript)\s*:/i', $m[3] ) ) {
				return ' ' . $m[1] . '=' . $m[2];
			}
			return $m[0];
		},
		$html
	);

	$allowed = array_keys( testimonial_rotator_cite_allowed_html() );
	$html    = preg_replace_callback(
		'/<\/?([a-z0-9]+)(\s[^>]*)?>/i',
		function ( $m ) use ( $allowed ) {
			return in_array( strtolower( $m[1] ), $allowed, true ) ? $m[0] : '';
		},
		$html
	);

	return $html;
}

/**
 * Sanitize a heading tag name used as a raw HTML element.
 * strip_tags() is not enough: "img src=x onerror=alert(1)" has no tags.
 *
 * @param mixed $tag
 * @return string
 */
function testimonial_rotator_sanitize_heading( $tag ) {
	$tag     = strtolower( preg_replace( '/[^a-z0-9]/i', '', (string) $tag ) );
	$allowed = array( 'h1', 'h2', 'h3', 'h4', 'h5', 'h6', 'p', 'div', 'span' );

	return in_array( $tag, $allowed, true ) ? $tag : 'h2';
}

/**
 * Strip quotes and other characters that can break out of a class="" attribute.
 *
 * @param mixed $classes
 * @return string
 */
function testimonial_rotator_sanitize_extra_classes( $classes ) {
	$classes = preg_replace( '/[^A-Za-z0-9_\-\s]/', '', (string) $classes );
	$classes = trim( preg_replace( '/\s+/', ' ', $classes ) );

	return $classes;
}

/**
 * Allow-list rotator JS transition names.
 *
 * @param mixed $fx
 * @return string
 */
function testimonial_rotator_sanitize_fx( $fx ) {
	$allowed = array( 'fade', 'fadeout', 'scrollHorz', 'scrollVert', 'flipHorz', 'flipVert', 'none' );

	return in_array( $fx, $allowed, true ) ? $fx : 'fade';
}

/**
 * Allow-list template slugs and reject path traversal.
 *
 * @param mixed $template
 * @return string
 */
function testimonial_rotator_sanitize_template( $template ) {
	$template = strtolower( (string) $template );

	if ( false !== strpos( $template, '..' ) || false !== strpos( $template, '/' ) || false !== strpos( $template, '\\' ) ) {
		return 'default';
	}

	$template = preg_replace( '/[^a-z0-9_-]/', '', $template );
	$allowed  = array( 'default', 'longform', 'onepig', 'twopigs', 'threepigs', 'starrynight', 'headlined' );

	return in_array( $template, $allowed, true ) ? $template : 'default';
}

/**
 * Plain text for values that must never contain markup (item reviewed, etc.).
 *
 * @param mixed $text
 * @return string
 */
function testimonial_rotator_sanitize_plain_text( $text ) {
	return trim( strip_tags( (string) $text ) );
}

/**
 * Image size slug for get_the_post_thumbnail().
 *
 * @param mixed $size
 * @return string
 */
function testimonial_rotator_sanitize_img_size( $size ) {
	$size = preg_replace( '/[^a-z0-9_\-]/i', '', (string) $size );
	return $size ? $size : 'thumbnail';
}

/**
 * Star rating 0–5.
 *
 * @param mixed $rating
 * @return int
 */
function testimonial_rotator_sanitize_rating( $rating ) {
	$rating = (int) $rating;
	if ( $rating < 0 ) {
		$rating = 0;
	}
	if ( $rating > 5 ) {
		$rating = 5;
	}
	return $rating;
}

/**
 * Keep only IDs that belong to the testimonial_rotator post type.
 *
 * @param mixed $ids
 * @return array
 */
function testimonial_rotator_sanitize_rotator_ids( $ids ) {
	$clean = array();
	foreach ( (array) $ids as $id ) {
		$id = function_exists( 'absint' ) ? absint( $id ) : abs( (int) $id );
		if ( ! $id ) {
			continue;
		}
		if ( function_exists( 'get_post_type' ) && 'testimonial_rotator' !== get_post_type( $id ) ) {
			continue;
		}
		$clean[] = $id;
	}
	return $clean;
}

/**
 * Display-safe cite HTML (kses + wpautop).
 *
 * @param mixed $cite
 * @return string
 */
function testimonial_rotator_kses_cite_output( $cite ) {
	$cite = testimonial_rotator_sanitize_cite( $cite );
	if ( function_exists( 'wpautop' ) ) {
		$cite = wpautop( $cite );
	}
	if ( function_exists( 'wp_kses' ) ) {
		return wp_kses( $cite, testimonial_rotator_cite_allowed_html() );
	}
	return $cite;
}

/**
 * True when this request may persist plugin post meta.
 *
 * @param int $post_id
 * @return bool
 */
function testimonial_rotator_can_save_meta( $post_id ) {
	if ( defined( 'DOING_AUTOSAVE' ) && DOING_AUTOSAVE ) {
		return false;
	}
	if ( function_exists( 'wp_is_post_revision' ) && wp_is_post_revision( $post_id ) ) {
		return false;
	}
	if ( function_exists( 'wp_is_post_autosave' ) && wp_is_post_autosave( $post_id ) ) {
		return false;
	}
	if ( empty( $_POST['testimonial_rotator_nonce'] ) || ! wp_verify_nonce( sanitize_text_field( wp_unslash( $_POST['testimonial_rotator_nonce'] ) ), 'testimonial_rotator_save' ) ) {
		return false;
	}
	if ( ! current_user_can( 'edit_post', $post_id ) ) {
		return false;
	}
	return true;
}

/**
 * Caps granted to Administrators and roles in the creator-role setting.
 *
 * @return array
 */
function testimonial_rotator_rotator_caps() {
	return array(
		'edit_testimonial_rotator',
		'read_testimonial_rotator',
		'delete_testimonial_rotator',
		'edit_testimonial_rotators',
		'edit_others_testimonial_rotators',
		'publish_testimonial_rotators',
		'read_private_testimonial_rotators',
		'delete_testimonial_rotators',
		'delete_private_testimonial_rotators',
		'delete_published_testimonial_rotators',
		'delete_others_testimonial_rotators',
		'edit_private_testimonial_rotators',
		'edit_published_testimonial_rotators',
		'create_testimonial_rotators',
	);
}

/**
 * Grant or revoke rotator CPT caps so menu hiding matches real access.
 */
function testimonial_rotator_sync_rotator_caps() {
	if ( ! function_exists( 'wp_roles' ) ) {
		return;
	}

	$allowed_roles = array( 'administrator' );
	foreach ( (array) get_option( 'testimonial-rotator-creator-role' ) as $role_name ) {
		$role_name = sanitize_key( $role_name );
		if ( $role_name && 'administrator' !== $role_name ) {
			$allowed_roles[] = $role_name;
		}
	}

	$caps = testimonial_rotator_rotator_caps();
	foreach ( array_keys( wp_roles()->roles ) as $role_name ) {
		$role = get_role( $role_name );
		if ( ! $role ) {
			continue;
		}
		$grant = in_array( $role_name, $allowed_roles, true );
		foreach ( $caps as $cap ) {
			if ( $grant ) {
				$role->add_cap( $cap );
			} else {
				$role->remove_cap( $cap );
			}
		}
	}
}

/**
 * Sync rotator caps when the creator-role option changes.
 */
function testimonial_rotator_maybe_sync_rotator_caps() {
	$hash = md5( wp_json_encode( get_option( 'testimonial-rotator-creator-role' ) ) . '3.0.4' );
	if ( get_option( 'testimonial-rotator-caps-sync' ) === $hash ) {
		return;
	}
	testimonial_rotator_sync_rotator_caps();
	update_option( 'testimonial-rotator-caps-sync', $hash, false );
}
