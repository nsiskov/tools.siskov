<?php
require_once 'abstractController.php';
class Base64Controller extends AbstractController {
	function process() {
		if (isset($_POST['srctext'])) {
			$source = $_POST['srctext'];
			$result = base64_decode($source);
			header('Content-Disposition: attachment; filename=decoded.bin');
			header('Content-type: application/octet-stream');
			ob_clean();
			echo $result;
			ob_end_flush();
			return array('render'=>false);
		}
		return array('render'=>true);
	}
}
?>