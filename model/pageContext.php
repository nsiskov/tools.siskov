<?php
class PageContext {
	public $canonicalUrl;
	public $pageId;
	
	private $texts;
	public $lang;
	
	function __construct($pageId, $texts, $lang) {
		
		$messages = $texts->messages[$pageId];
		$this->canonicalUrl = $_SERVER['HTTP_HOST'] . '/' . $lang . '/' . $pageId . '.html';
		$this->pageId = $pageId;
		$this->texts = $messages;
		$this->lang = $lang;
	}
	
	function __get($property) {
		return $this->texts[$property];
	}
	
	function __isset($property) {
		if (isset($this->texts[$property])) {
			return true;
		} 
		return false;
	}
}
?>