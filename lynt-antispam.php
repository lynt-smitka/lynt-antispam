<?php
/*
Plugin Name: Lynt Antispam
Author: Vladimir Smitka
Description: ALFA VERSION! - Antispam plugin using DNSBL at http://www.projecthoneypot.org and honeypot field
Version: 0.0.1
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
    add_action('comment_form_after_fields', array($this, 'lynt_antispam_honeypot'));
    if (!is_admin()) {
      add_filter('preprocess_comment', array($this, 'lynt_antispam_blocker'));
    }
  }

  function httpbl($ip)
  {
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

  function lynt_antispam_honeypot()
  {
    if (!is_user_logged_in()) {
      echo '<p style="display: none;"><label>Do not fill: </label><input type="text" name="nick" /></p>';
    }
  }

  function lynt_antispam_blocker($data)
  {
    if (!empty($_POST['nick']) || $this->httpbl($ip)) {
      wp_die("Sorry, your comment doesn't pass the antispam...");
    }

    return $data;
  }
}

new LyntAntiSpam();

?>
