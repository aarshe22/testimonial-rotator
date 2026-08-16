<?php

global $post;

// WRAPPER
$hclass = $show_microdata ? 'hreview itemreviewed' : '';
echo "<div class=\"testimonial_rotator testimonial_rotator_single template-{$template_name} {$hclass} item {$has_image} cf-tr\">\n";		

// IF SHOW TITLE
if( $show_title ) 
{
	echo "<{$title_heading} class=\"testimonial_rotator_slide_title\">" . get_the_title() . "</{$title_heading}>\n";
	echo "<hr class=\"headlined_hr\">";
}

// RATING
if( $rating AND $show_stars )
{
	echo "<div class=\"testimonial_rotator_stars cf-tr\">\n";
	for($r=1; $r <= $rating; $r++)
	{
		echo "	<span class=\"testimonial_rotator_star testimonial_rotator_star_$r\"><i class=\"fa {$testimonial_rotator_star}\"></i></span>";
	}
	echo "</div>\n";
}

// DESCRIPTION
echo "<div class=\"text testimonial_rotator_description\">\n";

// CONTENT
if( $show_body )
{
	echo "<div class=\"testimonial_rotator_quote\">\n";
	echo get_the_content();
	echo "</div>\n";
}

// AUTHOR INFO
if( $cite AND $show_author )
{
	if ( $has_image AND $show_image )echo "	<div class=\"testimonial_rotator_img img\">" . get_the_post_thumbnail( get_the_ID(), $img_size) . "</div>\n"; 
	echo "<div class=\"testimonial_rotator_author_info cf-tr\">\n";
	echo testimonial_rotator_kses_cite_output( $cite );
	echo "</div>\n";				
}

echo "</div>\n";
	
// MICRODATA 
if( $show_microdata )
{
	if( !$itemreviewed ) $itemreviewed = get_bloginfo('name');
	
	echo "	<div class=\"testimonial_rotator_microdata\">\n";
		if($itemreviewed) echo "\t<div class=\"item\"><div class=\"fn\">" . esc_html( $itemreviewed ) . "</div></div>\n";
		if($rating) echo "\t<div class=\"rating\">{$rating}</div>\n";

		echo "	<div class=\"dtreviewed\"> " . get_the_date('c') . "</div>";
		echo "	<div class=\"reviewer\"> ";
			echo "	<div class=\"fn\"> " . testimonial_rotator_kses_cite_output( $cite ) . "</div>";
			if ( has_post_thumbnail() ) { echo get_the_post_thumbnail( get_the_ID(), 'thumbnail', array('class' => 'photo' )); }
		echo "	</div>";
		echo "	<div class=\"summary\"> " . testimonial_rotator_excerpt(apply_filters('testimonial_rotator_microdata_summary_length', 300)) . "</div>";
		echo "	<div class=\"permalink\"> " . get_permalink() . "</div>";
	echo "	</div><!-- .testimonial_rotator_microdata -->\n";
}

echo "</div>\n";