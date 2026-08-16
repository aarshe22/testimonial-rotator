<?php

// Exit if accessed directly
if ( ! defined( 'ABSPATH' ) && ! defined( 'TESTIMONIAL_ROTATOR_TESTING' ) ) {
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
 * Allow-list kses used in unit tests and as a defense-in-depth pass in WordPress.
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
