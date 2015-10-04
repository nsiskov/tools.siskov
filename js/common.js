/**
 * Siskov.info
 * 
 */

function charcount(srcElementId, dstElementId) {
	var sourceCnt = document.getElementById(srcElementId);
	var count = sourceCnt.value.length;
	$('#' + dstElementId).html(count);
}

function load(event) {
	//initialize main navigation
	$(".subnav").mouseenter(function() {
		$(".subnav ul.opened").each(function() {
			$(this).removeClass('opened');
			$(this).fadeOut(100);
		});
		$(this).find("ul").fadeTo(100, 1).addClass('opened');
	});
	
	
	$(".subnav").mouseleave(function () {
		$(this).find("ul").removeClass('opened');
		$(this).find("ul").fadeOut(100);
	}); 
	
	if(window.location.hash) {
	      var hsh = window.location.hash.substring(1);
	      if (hsh.length > 3) {
		      var source = hsh.substring(3);
		      document.getElementById("srctext").value = Base64.decode(source);
		      charcount('srctext','srccharcnt');
		      window.location.hash = '';
		      history.pushState('', document.title, window.location.pathname);
	      }
	  } else {
	      // No hash found
	  }
	
	// js file support
	if (window.File && window.FileReader && window.FileList && window.Blob) {
		$("#fileLoad").show();
		document.getElementById('filesrc').addEventListener('change', readSingleFile, false);
	} else {
		//browser does not support file API
	}
}

function readSingleFile(evt) {
    var f = evt.target.files[0]; 

    if (f) {
      var r = new FileReader();
      r.onload = function(e) {
	      var contents = e.target.result;
	      var mime = f.type;
	      if (isTextFile(f)) {
	    	  document.getElementById("srctext").value=contents;
	    	  charcount('srctext','srccharcnt');
	      } else {
	    	  if(isSupported()) {
		    	  var startIndex = contents.indexOf(',');
		    	  $('#srcblock').hide();
		    	  $('#toolactions').hide();
		    	  $('#srcfileloaded').show();
		    	  setDst(contents.substring(startIndex + 1));
		    	  $('#fileType').html(f.type);
		    	  $('#fileName').html(f.name);
		    	  $('#fileSize').html(f.size);
		    	  $('#dataUrlPrefix').html(contents.substring(0, startIndex));
	    	  } else {
	    		  alert("only text files are supported");
	    	  }
	      }
      }
      var mime = f.type;
      if (isTextFile(f)) {
    	  r.readAsText(f);
      } else {
    	  r.readAsDataURL(f);
      }
    } else { 
      alert("Failed to load file");
    }
  }

function isTextFile(f) {
	return f.type != null && f.type.indexOf('text') != -1;
}

function isSupported() {
	if (window.location.href.indexOf('base64') != -1) {
		return true;
	}
	return false;
}

function openFileDialog(event) {
	noDefault(event);
	$('.file-wrapper input').click();
}
 

function transfer(event, url) {
	noDefault(event);
	url += '?rnd=' + Math.random();
	url += '#src_' + Base64.encode(document.getElementById("dsttext").value);
	window.location = url;
	return false;
}

function stripUml(event) {
	noDefault(event);
	var text = UNorm.nfd(getSrc());
	var reg = new RegExp("[^\x00-\x7F]", "gm");
	text = text.replace(reg, '');
	setDst(text);
	return false;
}

function tobase64(event) {
	noDefault(event);
	setDst(Base64.encode(getSrc()));
	return false;
}
function frombase64(event) {
	noDefault(event);
	setDst(Base64.decode(getSrc()));
	
	return false;
}

function tomd5() {
	setDst(hex_md5(getSrc()));
	return false;
}

function tohtpasswd() {
	var username = $("#username").val();
	var password = $("#password").val();
	
	if (username == null || username.length == 0) {
		$("#username").focus();
		return;
	}
	if (password == null || password.length == 0) {
		$("#password").focus();
		return;
	}
	
	var passCr = htpasswd(username, password);
	$("#resultSection").show();
	document.getElementById("dsttextcrypt").value=passCr.crypt;
	document.getElementById("dsttextmd5").value=passCr.md5;
	document.getElementById("dsttextsha1").value=passCr.sha1;
}

function tosha1hex() {
	setDst(hex_sha1(getSrc()));
	
	return false;
}
function tosha1b64() {
	setDst(b64_sha1(getSrc()));
	
	return false;
}
function tosha256hex() {
	setDst(hex_sha256(getSrc()));
	
	return false;
}
function tosha256b64() {
	setDst(b64_sha256(getSrc()));
	
	return false;
}
function tosha512hex() {
	setDst(hex_sha512(getSrc()));
	
	return false;
}
function tosha512b64() {
	setDst(b64_sha512(getSrc()));
	
	return false;
}
function tohmacsha1hex() {
	setDst(hex_hmac_sha1(getKey(), getSrc()));
	
	return false;
}
function tohmacsha1b64() {
	setDst(b64_hmac_sha1(getKey(), getSrc()));
	
	return false;
}
function tohmacsha256hex() {
	setDst(hex_hmac_sha256(getKey(), getSrc()));
	return false;
}
function tohmacsha256b64() {
	setDst(b64_hmac_sha256(getKey(), getSrc()));
	return false;
}
function tohmacsha512hex() {
	setDst(hex_hmac_sha512(getKey(), getSrc()));
	return false;
}
function tohmacsha512b64() {
	setDst(b64_hmac_sha512(getKey(), getSrc()));
	return false;
}
function tohmacmd5hex() {
	setDst(hex_hmac_md5(getKey(), getSrc()));
	return false;
}
function tohmacmd5b64() {
	setDst(b64_hmac_md5(getKey(), getSrc()));
	return false;
}
function tohtml() {
	setDst(Html.encode(getSrc()));
	return false;
}
function fromhtml() {
	setDst(Html.decode(getSrc()));
	return false;
}

function tourl() {
	setDst(encodeURIComponent(getSrc()));
	return false;
}
function fromurl() {
	setDst(decodeURIComponent(getSrc()));
	return false;
}

function getSrc() {
	return document.getElementById("srctext").value;
}

function setDst(dst) {
	$("#resultSection").show();
	document.getElementById("dsttext").value=dst;
	charcount('dsttext', 'dstcharcnt');
}
function getKey() {
	return document.getElementById("srckey").value;
	
}

function noDefault(event) {
	if(event.preventDefault) {
		event.preventDefault();
	} else { 
		event.returnValue = false; 
	}
}

function selectResult(event) {
	noDefault(event);
	document.getElementById("dsttext").focus();
	document.getElementById("dsttext").select();
}