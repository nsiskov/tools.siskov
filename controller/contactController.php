<?php
require_once 'abstractController.php';
class ContactController extends AbstractController {
	function process() {
		$ret = array('render'=>true);
		if (isset($_POST['message'])) {
			$message = $_POST['message'];
			if (isset($message)) {
				$contactSuccess = false;
				date_default_timezone_set('UTC');
				$fileName = 'contact/msg' . strtotime("yyyyMMddHHmmss") . uniqid('', true) .'.txt';
				$message = "CLIENT: " . $this->getip() . "\nMESSAGE:\n" . $message;
				$this->writeFile($fileName, $message);
				$contactSuccess = true;
				$ret = array_merge($ret, array('contactSuccess'=>$contactSuccess));
			}
		}
		return $ret;
	}

	private function writeFile($file, $content) {
		$old = null;
		$dir = dirname($file);
		if (!is_dir($dir)) {
			$old = umask(0000);
			if (false === @mkdir($dir, 0777, true) && !is_dir($dir)) {
				throw new RuntimeException(sprintf("Unable to create the cache directory (%s).", $dir));
			}
		} elseif (!is_writable($dir)) {
			throw new RuntimeException(sprintf("Unable to write in the cache directory (%s).", $dir));
		}

		$tmpFile = tempnam(dirname($file), basename($file));
		if (false !== @file_put_contents($tmpFile, $content)) {
			// rename does not work on Win32 before 5.2.6
			if (@rename($tmpFile, $file) || (@copy($tmpFile, $file) && unlink($tmpFile))) {
				@chmod($file, 0777);
				umask($old);
				return;
			}
		}

		throw new RuntimeException(sprintf('Failed to write file "%s".', $file));
	}

	function validip($ip) {
		if (!empty($ip) && ip2long($ip)!=-1) {
			$reserved_ips = array (
					array('0.0.0.0','2.255.255.255'),
					array('10.0.0.0','10.255.255.255'),
					array('127.0.0.0','127.255.255.255'),
					array('169.254.0.0','169.254.255.255'),
					array('172.16.0.0','172.31.255.255'),
					array('192.0.2.0','192.0.2.255'),
					array('192.168.0.0','192.168.255.255'),
					array('255.255.255.0','255.255.255.255')
			);

			foreach ($reserved_ips as $r) {
				$min = ip2long($r[0]);
				$max = ip2long($r[1]);
				if ((ip2long($ip) >= $min) && (ip2long($ip) <= $max)) return false;
			}
			return true;
		} else {
			return false;
		}
	}

	function getip() {
		if ($this->validip($_SERVER["HTTP_CLIENT_IP"])) {
			return $_SERVER["HTTP_CLIENT_IP"];
		}

		foreach (explode(",",$_SERVER["HTTP_X_FORWARDED_FOR"]) as $ip) {
			if ($this->validip(trim($ip))) {
				return $ip;
			}
		}

		if ($this->validip($_SERVER["HTTP_X_FORWARDED"])) {
			return $_SERVER["HTTP_X_FORWARDED"];

		} elseif ($this->validip($_SERVER["HTTP_FORWARDED_FOR"])) {
			return $_SERVER["HTTP_FORWARDED_FOR"];

		} elseif ($this->validip($_SERVER["HTTP_FORWARDED"])) {
			return $_SERVER["HTTP_FORWARDED"];

		} elseif ($this->validip($_SERVER["HTTP_X_FORWARDED"])) {
			return $_SERVER["HTTP_X_FORWARDED"];

		} else {
			return $_SERVER["REMOTE_ADDR"];
		}
	}
}
?>