<?php
/*
Plugin Name: Lynt Antispam
Author: Vladimir Smitka
Description: ALFA VERSION! - Antispam plugin using DNSBL at http://www.projecthoneypot.org and honeypot field
Version: 0.0.2
Author URI: https://lynt.cz
License: GPLv2 or later
*/
/*
This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
*/
//you need API key from http://www.projecthoneypot.org
define("LYNT_PROJECT_HONEYPOT_KEY", "");

class LyntAntiSpam {

 function LyntAntiSpam()
  {
    add_action('comment_form_after_fields',  array($this, 'lynt_antispam_honeypot'));
    add_filter('comment_form_field_comment', array($this, 'lynt_antispam_replace' ));
    add_action('init', array($this, 'lynt_antispam_revert'));
    if (!is_admin()) {
      add_filter('preprocess_comment', array($this, 'lynt_antispam_blocker'));
    }
  }
  
  
  //test IP with project honeypot  
  function httpbl($ip)
  {
    if(!(defined('LYNT_PROJECT_HONEYPOT_KEY') && LYNT_PROJECT_HONEYPOT_KEY)) return false;
    $lookup = LYNT_PROJECT_HONEYPOT_KEY . '.' . implode('.', array_reverse(explode('.', $ip))) . '.dnsbl.httpbl.org';
    $result = explode('.', gethostbyname($lookup));
    /*
    type:
    0 - Search Engine
    1 - Suspicious
    2 - Harvester
    4 - Comment Spammer
    */
    if ($result[0] == 127) {
      $activity = $result[1];
      $threat = $result[2];
      $type = $result[3];
      if (($type >= 4 && $threat > 5) || ($type > 0 && $threat > 30)) return true;
    }
    return false;
  }
  
  
  //super easy word blacklist
  function lynt_blacklist_strings($comment)
  {
    $bl = ['[url=', 'pill', 'viagra', 'cailis', 'replica'];
    
    foreach($bl as $string) {
      if (stripos($comment, $string) !== FALSE) return true;
    }
    return false;
  }
  
  
  //block direct requests
  function lynt_block_referer()
  {
    if (strpos($_SERVER["HTTP_REFERER"], get_site_url()) !== FALSE) return false;
    return true;
  }
  
  
  //add honeypot fields
  function lynt_antispam_honeypot()
  {
    if (!is_user_logged_in()) {
      echo '<p style="display: none;"><label>Do not fill: </label><input type="text" name="nick" id="nick" /><br /><textarea id="comment" name="comment"></textarea></p>';
    }
  }
  
  
  //replace regular comment field id and name
  function lynt_antispam_replace($field)
  {
    $replaced = str_replace('="comment"', '="lynt-comment"', $field);
    return $replaced;
  }
  
  
  //revert the comment field 
  function lynt_antispam_revert($field)
  {
    if (basename($_SERVER['PHP_SELF']) == 'wp-comments-post.php' && isset($_POST) && isset($_POST['lynt-comment']) && isset($_POST['comment'])) {
      $comment = $_POST['lynt-comment'];
      $_POST['lynt-comment'] = $_POST['comment'];
      $_POST['comment'] = $comment;
    }
  }
  
  
  //antispam tests
  function lynt_antispam_blocker($data)
  {
    if (!empty($_SERVER['HTTP_CLIENT_IP'])) {
      $ip = $_SERVER['HTTP_CLIENT_IP'];
    }
    elseif (!empty($_SERVER['HTTP_X_FORWARDED_FOR'])) {
      $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
    }
    else {
      $ip = $_SERVER['REMOTE_ADDR'];
    }
    if (!empty($_POST['nick']) || !empty($_POST['lynt-comment']) || $this->lynt_block_referer() || $this->lynt_blacklist_strings($data['comment_content']) || $this->httpbl($ip)) {
      wp_die("You shall not pass through antispam...");
    }
    $data['comment'] = $data['lynt-comment'];
    return $data;
  }
}
new LyntAntiSpam();
?>
