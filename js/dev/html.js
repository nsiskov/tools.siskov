var Html = {
	encode: function(src) {
		var res = "";
		for ( var i = 0; i < src.length; i++ ) {
			res += '&#' + src.charCodeAt(i) + ';';
		}
		
		return res;
	},

	decode: function(src) {
		var inside = false;
		var skip = false;
		var i = 0;
		var res = "";
		var num = "";
		while (i < src.length) {
			if (src.charAt(i) == '&') {
				if (inside) {
					res +='&#';
				}
				res += num;
				num = "";
				for (var j = i + 1; j < src.length; j++) {
					if (src.charAt(j) == '#') {
						inside = true;
						skip = true;
						i += 1;
					} else {
						inside = false;
					}
					break;
				}
			}
			
			if (inside && src.charAt(i) == ';') {
				inside = false;
				var number = num.match(/^\d+$/gi); 
				if (number != null) {
					var int = parseInt(num);
					res += String.fromCharCode(int);
				} else {
					res += '&#' + num + ";";
				}
				num = "";
				skip = true;
			}
			
			if (skip) {
				skip = false;
			} else {
				if (inside) {
					num += src.charAt(i);
				} else {
					res += src.charAt(i);
				}
			}
			i++;
		}
		return res + num;
	}
}