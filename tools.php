<?php
require_once 'lib/Twig/Autoloader.php';
Twig_Autoloader::register();
$loader = new Twig_Loader_Filesystem('view');
$twig = new Twig_Environment($loader, array(
		'cache' => 'cache',
		
));
require_once 'textResources.php';
require_once 'model/pageContext.php';
session_start();


$pageId = determinePage();
if ($pageId == "") {
	header('Location: base64.html');
} else {
	$lang = determineLanguage();
	 
	$textResources = new TextResources($lang);
	$pageContext = new PageContext($pageId, $textResources, $lang);
	
	$twigVars = array('host'=>"http://" . $_SERVER['HTTP_HOST'], 'textResources'=>$textResources, 'pageContext'=>$pageContext);
	$twigTemplate = $pageId;
	$render = true;
	$controller = null;
	
	switch ($pageId) {
		case 'sha1':
			$twigVars['sha'] = '1';
			$twigTemplate = 'sha';
			break;
		case 'sha256':
			$twigVars['sha'] = '256';
			$twigTemplate = 'sha';
			break;
		case 'sha512':
			$twigVars['sha'] = '512';
			$twigTemplate = 'sha';
			break;
		case 'hmacsha1':
			$twigVars['hmac'] = 'sha1';
			$twigTemplate = 'hmac';
			break;
		case 'hmacsha256':
			$twigVars['hmac'] = 'sha256';
			$twigTemplate = 'hmac';
			break;
		case 'hmacsha512':
			$twigVars['hmac'] = 'sha512';
			$twigTemplate = 'hmac';
			break;
		case 'hmacmd5':
			$twigVars['hmac'] = 'md5';
			$twigTemplate = 'hmac';
			break;
		case 'base64':
			require_once 'controller/base64Controller.php';
			$controller = new Base64Controller();
			break;
		case 'contact':
			require_once 'controller/contactController.php';
			$controller = new ContactController();
	}
	
	if (isset($controller)) {
		$vars = $controller->process();
		$render = $vars['render'];
		$twigVars = array_merge($twigVars, $vars);
	}
	
	if ($render===true) {
		echo $twig->render('page/' . $twigTemplate . '.twig', $twigVars);
	}
}

function determinePage() {
	$pageId = "";
	if (isset($_GET['t'])) {
		$pageId =  $_GET['t'];
	}

	if(false === array_search($pageId,
			array('base64','md5','sha1','sha256','sha512','hmacsha1'
					,'hmacsha256','hmacsha512','hmacmd5','html','htpasswd','url','contact'))) {
		$pageId = "";
	}
	return $pageId;
}

function determineLanguage() {
	if (isset($_GET['lng'])) {
		//set the language from the lng parameter (overrides all other cases)
		$lang =  $_GET['lng'];
	} else {
		if ($_SESSION['lang']) {
			$sesLng = $_SESSION['lang'];
			//set the session language as first option (if any)
			$lang = $sesLng;
		} else {
			$reqLang = getLangFromRequest();
			if (isset($reqLang)) {
				//set the requrest language (from browser) as second option (if any)
				$lang = $reqLang;
			}
		}
	}
	 
	if (false === array_search($lang, array('en','de'))) {
		$lang = 'en';
	}
	 
	return $lang;
}

function getLangFromRequest() {
	$aclang = getallheaders();
	$lngHead = $aclang['Accept-Language'];
	if (isset($lngHead)) {
		$chk = explode(";", $lngHead);
		$chunks = $chk[0];
		foreach (explode(",",$chunks) as $entry) {
			if(strlen($entry) == 2) {
				return $entry;
			}
			if (strpos($entry, "-") != -1 && strlen($entry) == 5) {
				$chkd = explode("-",$entry);
				return $chkd[0];
			}
		}
	}
}

function getallheaders()
{
	$headers = '';
	foreach ($_SERVER as $name => $value)
	{
		if (substr($name, 0, 5) == 'HTTP_')
		{
			$headers[str_replace(' ', '-', ucwords(strtolower(str_replace('_', ' ', substr($name, 5)))))] = $value;
		}
	}
	return $headers;
}

?>