//<!CDATA[
// ====================================================================
//       URLEncode and URLDecode functions
//
// Copyright Albion Research Ltd. 2002
// http://www.albionresearch.com/
//
// You may copy these functions providing that 
// (a) you leave this copyright notice intact, and 
// (b) if you use these functions on a publicly accessible
//     web site you include a credit somewhere on the web site 
//     with a link back to http://www.albionresearch.com/
//
// If you find or fix any bugs, please let us know at albionresearch.com
//
// SpecialThanks to Neelesh Thakur for being the first to
// report a bug in URLDecode() - now fixed 2003-02-19.
// And thanks to everyone else who has provided comments and suggestions.
// ====================================================================
function URLEncode( )
{
  var plaintext = document.URLForm.F1.value;
  if (document.URLForm.RFC2396.checked) {  // OLD Browser mode
    // The Javascript escape and unescape functions do not correspond
    // with what browsers actually do...
    var SAFECHARS = "0123456789" +					// Numeric
		        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +	// Alphabetic
		        "abcdefghijklmnopqrstuvwxyz" +
		        "-_.!~*'()";					// RFC2396 Mark characters
    var HEX = "0123456789ABCDEF";

    var encoded = "";
    for (var i = 0; i < plaintext.length; i++ ) {
      var ch = plaintext.charAt(i);
        if (ch == " ") {
          encoded += "+";				// x-www-urlencoded, rather than %20
      } else if (SAFECHARS.indexOf(ch) != -1) {
          encoded += ch;
      } else {
          var charCode = ch.charCodeAt(0);
        if (charCode > 255) {
            alert( "Unicode Character '" 
                          + ch 
                          + "' cannot be encoded using standard RFC2396 encoding.\n" +
	                  "(URL encoding only supports 8-bit characters.)\n" +
			          "A space (+) will be substituted." );
	        encoded += "+";
        } else {
	        encoded += "%";
	        encoded += HEX.charAt((charCode >> 4) & 0xF);
	        encoded += HEX.charAt(charCode & 0xF);
        }
      }
    } // for

    document.URLForm.F2.value = encoded;
  } else {  // Modern browser mode
    document.URLForm.F2.value = encodeURIComponent(plaintext);
  }
  document.URLForm.F2.select();
	return false;
};

function URLDecode( )
{
   var encoded = document.URLForm.F2.value;
   if (document.URLForm.RFC2396.checked) {  // OLD Browser mode
     // Replace + with ' '
     // Replace %xx with equivalent character
     // Put [ERROR] in output if %xx is invalid.
     var HEXCHARS = "0123456789ABCDEFabcdef"; 
     var plaintext = "";
     var i = 0;
     while (i < encoded.length) {
       var ch = encoded.charAt(i);
	     if (ch == "+") {
	         plaintext += " ";
		     i++;
	     } else if (ch == "%") {
			  if (i < (encoded.length-2) 
					  && HEXCHARS.indexOf(encoded.charAt(i+1)) != -1 
					  && HEXCHARS.indexOf(encoded.charAt(i+2)) != -1 ) {
				  plaintext += unescape( encoded.substr(i,3) );
				  i += 3;
			  } else {
				  alert( 'Bad escape combination near ...' + encoded.substr(i) );
				  plaintext += "%[ERROR]";
				  i++;
			  }
		  } else {
		     plaintext += ch;
		     i++;
		  }
	  } // while
     document.URLForm.F1.value = plaintext;
   } else { // Modern browser mode
     try {
         document.URLForm.F1.value = decodeURIComponent(encoded);
     } catch (error) {
         alert( error + ' - Probably the second byte of a Unicode character is missing.' );
     }
   }
   document.URLForm.F1.select();
   return false;
};