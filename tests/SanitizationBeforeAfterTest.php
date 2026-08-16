<?php

use PHPUnit\Framework\TestCase;

/**
 * Before/after tests for the two 3.0.3 stored XSS issues.
 *
 * @group before  documents the 3.0.3 sanitizers (they fail — that is the point)
 * @group after   asserts the patched helpers block the same payloads
 */
class SanitizationBeforeAfterTest extends TestCase {

	private function render_title_html( $heading ) {
		return '<' . $heading . ' class="testimonial_rotator_slide_title">Great product</' . $heading . '>';
	}

	private function render_class_attribute( $extra_classes ) {
		return 'class="testimonial_rotator ' . $extra_classes . '"';
	}

	private function render_cite_html( $cite ) {
		return '<div class="testimonial_rotator_author_info">' . $cite . '</div>';
	}

	private function render_fx_attribute( $fx ) {
		return 'data-cycletwo-fx="' . $fx . '"';
	}

	/**
	 * 3.0.3 rotator save: strip_tags() only.
	 */
	private function legacy_sanitize_heading( $tag ) {
		return strip_tags( (string) $tag );
	}

	/**
	 * 3.0.3 templates and admin author_info column: echo stored cite with no escape.
	 */
	private function legacy_output_cite( $cite ) {
		return (string) $cite;
	}

	/**
	 * 3.0.3 shortcode/widget: extra_classes interpolated raw.
	 */
	private function legacy_sanitize_extra_classes( $classes ) {
		return (string) $classes;
	}

	/**
	 * 3.0.3 rotator save: strip_tags() on fx / template.
	 */
	private function legacy_strip_tags_only( $value ) {
		return strip_tags( (string) $value );
	}

	// -------------------------------------------------------------------------
	// Vulnerability 1: Author Information (_cite)
	// -------------------------------------------------------------------------

	/**
	 * @group before
	 */
	public function test_before_patch_cite_script_survives_in_admin_and_frontend_output() {
		$payload = '<script>alert(document.cookie)</script>Acme Inc';
		$html    = $this->render_cite_html( $this->legacy_output_cite( $payload ) );

		$this->assertStringContainsString( '<script>alert(document.cookie)</script>', $html );
	}

	/**
	 * @group before
	 */
	public function test_before_patch_cite_img_onerror_survives_output() {
		$payload = '<img src=x onerror=alert(1)>Jane Doe';
		$html    = $this->render_cite_html( $this->legacy_output_cite( $payload ) );

		$this->assertStringContainsString( 'onerror=alert(1)', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_cite_strips_script_tags() {
		$payload = '<script>alert(document.cookie)</script>Acme Inc';
		$html    = $this->render_cite_html( testimonial_rotator_sanitize_cite( $payload ) );

		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringNotContainsString( 'alert(document.cookie)', $html );
		$this->assertStringContainsString( 'Acme Inc', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_cite_strips_img_onerror() {
		$payload = '<img src=x onerror=alert(1)>Jane Doe';
		$html    = $this->render_cite_html( testimonial_rotator_sanitize_cite( $payload ) );

		$this->assertStringNotContainsString( '<img', $html );
		$this->assertStringNotContainsString( 'onerror', $html );
		$this->assertStringContainsString( 'Jane Doe', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_cite_strips_javascript_href() {
		$payload = '<a href="javascript:alert(1)">CEO</a>';
		$safe    = testimonial_rotator_sanitize_cite( $payload );

		$this->assertStringNotContainsString( 'javascript:', $safe );
		$this->assertStringContainsString( 'CEO', $safe );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_cite_keeps_safe_formatting() {
		$payload = '<strong>Jane Doe</strong>, <em>CEO</em> at <a href="https://example.com" title="Site">Acme</a>';
		$safe    = testimonial_rotator_sanitize_cite( $payload );

		$this->assertStringContainsString( '<strong>Jane Doe</strong>', $safe );
		$this->assertStringContainsString( '<em>CEO</em>', $safe );
		$this->assertStringContainsString( 'https://example.com', $safe );
	}

	// -------------------------------------------------------------------------
	// Vulnerability 2: title_heading + attribute injection
	// -------------------------------------------------------------------------

	/**
	 * @group before
	 */
	public function test_before_patch_heading_img_onerror_becomes_an_html_tag() {
		$payload = 'img src=x onerror=alert(1)';
		$heading = $this->legacy_sanitize_heading( $payload );

		$this->assertSame( $payload, $heading, 'strip_tags() does not touch a string with no < >' );

		$html = $this->render_title_html( $heading );
		$this->assertStringContainsString( '<img src=x onerror=alert(1)', $html );
		$this->assertStringContainsString( 'onerror=alert(1)', $html );
	}

	/**
	 * @group before
	 */
	public function test_before_patch_heading_onclick_attribute_survives() {
		$payload = 'h2 onclick=alert(1)';
		$html    = $this->render_title_html( $this->legacy_sanitize_heading( $payload ) );

		$this->assertStringContainsString( '<h2 onclick=alert(1)', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_heading_img_onerror_falls_back_to_h2() {
		$payload = 'img src=x onerror=alert(1)';
		$heading = testimonial_rotator_sanitize_heading( $payload );
		$html    = $this->render_title_html( $heading );

		$this->assertSame( 'h2', $heading );
		$this->assertSame( '<h2 class="testimonial_rotator_slide_title">Great product</h2>', $html );
		$this->assertStringNotContainsString( 'onerror', $html );
		$this->assertStringNotContainsString( '<img', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_heading_onclick_falls_back_to_h2() {
		$payload = 'h2 onclick=alert(1)';
		$heading = testimonial_rotator_sanitize_heading( $payload );
		$html    = $this->render_title_html( $heading );

		$this->assertSame( 'h2', $heading );
		$this->assertStringNotContainsString( 'onclick', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_heading_allow_list_preserves_safe_tags() {
		$this->assertSame( 'h1', testimonial_rotator_sanitize_heading( 'h1' ) );
		$this->assertSame( 'h3', testimonial_rotator_sanitize_heading( 'H3' ) );
		$this->assertSame( 'p', testimonial_rotator_sanitize_heading( 'p' ) );
		$this->assertSame( 'h2', testimonial_rotator_sanitize_heading( '' ) );
		$this->assertSame( 'h2', testimonial_rotator_sanitize_heading( 'script' ) );
	}

	/**
	 * @group before
	 */
	public function test_before_patch_extra_classes_break_out_of_class_attribute() {
		$payload = '" onmouseover="alert(1)';
		$html    = $this->render_class_attribute( $this->legacy_sanitize_extra_classes( $payload ) );

		$this->assertStringContainsString( 'onmouseover="alert(1)"', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_extra_classes_cannot_break_out_of_attribute() {
		$payload = '" onmouseover="alert(1)';
		$safe    = testimonial_rotator_sanitize_extra_classes( $payload );
		$html    = $this->render_class_attribute( $safe );

		$this->assertStringNotContainsString( '"', $safe );
		$this->assertDoesNotMatchRegularExpression( '/\sonmouseover\s*=/i', $html );
		$this->assertSame( 2, substr_count( $html, '"' ), 'class attribute must remain a single quoted string' );
	}

	/**
	 * @group before
	 */
	public function test_before_patch_fx_attribute_breakout() {
		$payload = 'fade" onfocus="alert(1)';
		$html    = $this->render_fx_attribute( $this->legacy_strip_tags_only( $payload ) );

		$this->assertStringContainsString( 'onfocus="alert(1)"', $html );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_fx_falls_back_to_fade() {
		$payload = 'fade" onfocus="alert(1)';
		$fx      = testimonial_rotator_sanitize_fx( $payload );
		$html    = $this->render_fx_attribute( $fx );

		$this->assertSame( 'fade', $fx );
		$this->assertSame( 'data-cycletwo-fx="fade"', $html );
	}

	/**
	 * @group before
	 */
	public function test_before_patch_template_path_traversal_survives_strip_tags() {
		$payload = '../../../wp-config';

		$this->assertSame( $payload, $this->legacy_strip_tags_only( $payload ) );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_template_rejects_path_traversal() {
		$this->assertSame( 'default', testimonial_rotator_sanitize_template( '../../../wp-config' ) );
		$this->assertSame( 'default', testimonial_rotator_sanitize_template( 'not-a-theme' ) );
		$this->assertSame( 'longform', testimonial_rotator_sanitize_template( 'longform' ) );
		$this->assertSame( 'default', testimonial_rotator_sanitize_template( 'default";alert(1)' ) );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_rating_is_clamped() {
		$this->assertSame( 0, testimonial_rotator_sanitize_rating( -3 ) );
		$this->assertSame( 5, testimonial_rotator_sanitize_rating( 99 ) );
		$this->assertSame( 3, testimonial_rotator_sanitize_rating( '3<script>' ) );
	}

	/**
	 * @group after
	 */
	public function test_after_patch_cite_output_helper_strips_script() {
		$html = testimonial_rotator_kses_cite_output( '<script>alert(1)</script><strong>Jane</strong>' );
		$this->assertStringNotContainsString( '<script>', $html );
		$this->assertStringContainsString( 'Jane', $html );
	}
}
