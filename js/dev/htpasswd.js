/**
 * Adapted from Apache's htpasswd 1.3 source code
 * http://httpd.apache.org/docs/programs/htpasswd.html
 * http://apache.dev.wapme.net/doxygen-1.3/htpasswd_8c-source.html
 * http://apache.dev.wapme.net/doxygen-1.3/ap__md5c_8c-source.html
 * http://apache.dev.wapme.net/doxygen-1.3/ap__sha1_8c-source.html
 * 
 */
var itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
function ap_to64(v, n) {
	var s = '';
	while (--n >= 0) {
		s += itoa64.charAt(v & 0x3f);
		v >>>= 6;
	}
	return s;
}

function stringToArray(s) {
	var a = [];
	for ( var i = 0; i < s.length; i++)
		a.push(s.charCodeAt(i));
	return a;
}

function createMd5Pass(password) {
	var salt = ap_to64(Math.floor(Math.random() * 16777215), 4)
			+ ap_to64(Math.floor(Math.random() * 16777215), 4);
	var head = "$apr1$" + salt;

	var msg = password + head;

	var final_ = str_md5(password + salt + password);
	for ( var pl = password.length; pl > 0; pl -= 16) {
		msg += final_.substr(0, (pl > 16) ? 16 : pl);
	}

	for (i = password.length; i != 0; i >>= 1)
		if (i & 1)
			msg += String.fromCharCode(0);
		else
			msg += password.charAt(0);
	final_ = str_md5(msg);

	var msg2;
	for (i = 0; i < 1000; i++) {
		msg2 = '';
		if (i & 1)
			msg2 += password;
		else
			msg2 += final_.substr(0, 16);
		if (i % 3)
			msg2 += salt;
		if (i % 7)
			msg2 += password;
		if (i & 1)
			msg2 += final_.substr(0, 16);
		else
			msg2 += password;
		final_ = str_md5(msg2);
	}
	final_ = stringToArray(final_);

	var cryptedPass = head + '$';
	cryptedPass += ap_to64((final_[0] << 16) | (final_[6] << 8) | final_[12], 4);
	cryptedPass += ap_to64((final_[1] << 16) | (final_[7] << 8) | final_[13], 4);
	cryptedPass += ap_to64((final_[2] << 16) | (final_[8] << 8) | final_[14], 4);
	cryptedPass += ap_to64((final_[3] << 16) | (final_[9] << 8) | final_[15], 4);
	cryptedPass += ap_to64((final_[4] << 16) | (final_[10] << 8) | final_[5], 4);
	cryptedPass += ap_to64(final_[11], 2);

	return cryptedPass;
}

function htpasswd(user, password) {
	var cryptPass = Javacrypt.displayPassword(password);
	var sha1Pass = "{SHA}" + b64_sha1(password);
	var md5Pass = createMd5Pass(password);

	var retVal = {
		'crypt' : user + ':' + cryptPass,
		'md5' : user + ':' + md5Pass,
		'sha1' : user + ':' + sha1Pass
	};
	return retVal;
}
