var key_count = 0;
var key_timer;
var key_timer_iter;
var key_updated = new Object();
var key_missing = new Object();

function encrypt() {
//error('encrypt');
try{
  if (window.crypto.getRandomValues) {
  	var pub_keys = get_pubkey($('#encrypt_to_ids').val());
  	//error('encrypt for '+JSON.stringify(pub_keys));
  	if (!pub_keys.length) {
  		error('need public key to encrypt a message');
  		return;
  	}
	$('#message').val(openpgp.write_encrypted_message(pub_keys,$('#message').val()));
	send_encrypted_text($('#message').val());
    //error("This message is going to be sent:\n" + $('#message').val());
    
  } else {
    $("#mybutton").val("browser not supported");
    error("Error: Browser not supported\nReason: We need a cryptographically secure PRNG to be implemented (i.e. the window.crypto method)\nSolution: Use Chrome >= 11, Safari >= 3.1 or Firefox >= 21");   
  }
  }catch(e){error(e.message)}
}

function encrypt_message(text,to) {
	try {
		var pub_keys = get_pubkey(to);
		return openpgp.write_encrypted_message(pub_keys,text);
	} catch(e) {
		// nothing
	}
}
	


function decrypt(message,who,passphrase) {
	if (!who) { 
		error('decrypt: missing who input');
		get_fb_uid(function(userid) {
			_decrypt(message,userid,passphrase);
		});
	} else {
		return _decrypt(message,who,passphrase);
	}
}
	
function _decrypt(message,who,passphrase) {
	error('get priv key for '+who);
	var priv_key = get_privkey(who);
	error(priv_key,1);
	
	if (priv_key == null) {
		error('need a private key to decrypt');
	}
	
	
	error('message in '+message);
	
	if (message == 'undefined') {
		error('undefined message');
		return;
	}
	
	//if (!message || typeof(message) != 'undefined') { message = $('#message').val() }
	//if () {error('decrypt missing message '+typeof(message));return}
	
	message = message.replace('...','');
	message = message.replace('See More','');
	message = message.replace(/ /g,'\r\n');
	message = message.replace('BEGIN\r\nPGP\r\nMESSAGE','BEGIN PGP MESSAGE');
	message = message.replace('END\r\nPGP\r\nMESSAGE','END PGP MESSAGE');
	
	error('raw '+message);
	
	var msg = openpgp.read_message(message);
	error('msg '+msg);
	if (msg[0].sessionKeys == null) {
		error('cannot find key ID for recipient <pre>'+msg[0].toString()+'</pre>');
		error('<pre>'+JSON.stringify(msg[0])+'</pre>');
		return;
	}
	error('msg '+JSON.stringify(msg));
	var keymat = null;
	var sesskey = null;
	error('sess '+msg.toString());
	//error('priv '+JSON.stringify(priv_key));
	for (var i=0; i<msg[0].sessionKeys.length;i++) {
		error('check priv key '+JSON.stringify({"priv_key":priv_key[0].obj.privateKeyPacket.publicKey.getKeyId(),"session_key":msg[0].sessionKeys[i].keyId.bytes}),1);
		if (priv_key[0].obj.privateKeyPacket.publicKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
			keymat = { key: priv_key[0], keymaterial: priv_key[0].obj.privateKeyPacket};
			sesskey = msg[0].sessionKeys[i];
			break;
		}
		if (priv_key[0].subKeys) {
			for (var j=0; j < priv_key[0].subKeys.length; j++) {
				if (priv_key[0].subKeys[j].publickKey.getKeyId() == msg[0].sessionKeys[i].keyId.bytes) {
					keymat = { key: priv_key[0], keymaterial: priv_key[0].subKeys[j]};
					sesskey = msg[0].sessionKeys[i];
					break;
				}
			}
		}
	}
	error('going to decrypt');
	var ret = 'failed to decrypt';
	if (keymat != null) {
		error('get passphrase');
		
		if (!keymat.keymaterial.decryptSecretMPIs(passphrase)) {
			error("Password for secret key is incorrect.");
			return;
		}
		ret = msg[0].decrypt(keymat, sesskey);
		$('#decrypted').text(ret);
	} else {
		error("no private key found.  no keymat.");
	}
	error('decrypt done: '+ret);
	return({"decrypted":ret});
}

function get_pubkey(search,callback) {
	error('search for pubkeys for '+search);
	var terms = search.split(',');
	var pubkeys = new Array();
	for (var i=0;i<terms.length;i++) {
		var user = terms[i].substr(1);
		try{
		var temp = openpgp.keyring.getPublicKeyForAddress(user);
		}catch(e){error(e.message)}
		error('found '+temp.length+' keys for '+user);
		if ((temp.length == 0 || !key_updated.hasOwnProperty(user)) && !key_missing.hasOwnProperty(user)) {
			
			get_facebook_pubkey(terms[i]);
			continue;
		}
		error('key found for '+terms[i]);
		error(JSON.stringify(temp));
		pubkeys = pubkeys.concat(temp);
		key_count--;
	}
	return pubkeys;
}

function get_facebook_pubkey(search_username) {
	var username = search_username.replace(/ /g,'.');
	var userdiv = $('#to_disp_'+username.substr(1).replace(/\W/g,''));

	error('get from facebook user '+username);
	$.get('https://www.facebook.com'+username+'/about',function(data) {
		var start = data.indexOf('-----BEGIN');
		if (start == -1) {
			start = data.indexOf('-\\-\\-\\-\\-BEGIN');
		}
		if (start > -1) {
			data = data.substring(start);
			error('found pgp key for '+username);
			var end = data.indexOf('-----END PGP PUBLIC KEY BLOCK-----');
			error('first end '+end);
			if (end == -1) {
				end = data.indexOf('-\\-\\-\\-\\-END PGP PUBLIC KEY BLOCK');
				error('second end '+end);
				end = end + 42;
			} else {
				end = end + 35;
			}
			var key_text = data.substring(0,end).replace(/<br \/>/g,'\r\n');
			key_text = key_text.replace(/\\-/g,'-');
			key_text = key_text.replace(/^\s*/mg,'');
			key_text = key_text.replace(/\s*$/mg,'');
			import_pubkey(key_text);
			key_updated[username.substr(1)] = 1;
			error('import_pubkey done');
			//error('loading from '+start+' to '+end);
			//error('key_text '+key_text,2);
			try {
				error('color is '+userdiv.css('color'));
				
				userdiv.css('color','rgb(0,255,0)');
			}catch(e){error('change to green error: '+e.message)}
		} else {
			error('nothing found for '+username.substr(1).replace(/\W/g,''));
			//error(data,1);
			userdiv.css('color','rgb(255,0,0)');
			key_missing[username.substr(1)] = 1;
		}
		key_count--;	
	});
}

function get_privkey(who) {
	return openpgp.keyring.getPrivateKeyForAddress(who);
}

function set_privkey(passphrase) {
	
	error('privkey is '+$('#privkey').val());
	error('set privkey passphrase '+passphrase);
	
	
	var priv_key = openpgp.read_privateKey($('#privkey').val());
	if (priv_key.length < 1) {
		error("no private key found.");
		return;
	}
	try{
	error('private key:\n'+$('#privkey').val());
	openpgp.keyring.importPrivateKey($('#privkey').val(),passphrase);
	openpgp.keyring.store();
	}catch(e){error('set_privkey '+e.message)}
	error('returning key:\n'+priv_key);
	return priv_key;
}

function import_privkey(passphrase) {
	return set_privkey(passphrase);
}

function import_pubkey(new_pubkey_text) {
	if (!new_pubkey_text) {
		new_pubkey_text = $('#pubkey').val();
	}
	error('import new pubkey to ring');
	error(new_pubkey_text,1);
	var new_pubkey = openpgp.read_publicKey(new_pubkey_text);
	try{
		if (new_pubkey != null) {
			error('import_pubkey got valid key text, importing');
			openpgp.keyring.importPublicKey(new_pubkey_text);
		}
	} catch(e) {
		error('import_pubkey error: '+e.message);
	}
}

function clearkeys() {
	var i=0;
	try{
	while (openpgp.keyring.exportPrivateKey(0)) {
		console.log('remove priv key '+i);
		openpgp.keyring.removePrivateKey(0);
		i++
	}
	}catch(e){error('clear priv '+i+': '+e.message)}
	error('cleared '+i+' priv keys');
	i=0;
	//error('pub '+JSON.stringify(openpgp.keyring.publicKeys));
	try{
	while (openpgp.keyring.exportPublicKey(0)) {
		openpgp.keyring.removePublicKey(0);
	}
	}catch(e){error('clear pub '+i+': '+e.message)}
	error('cleared '+i+' pub keys');
	openpgp.keyring.store();
}


function showkeys() {
	error(JSON.stringify(openpgp.keyring),1);
}

function showmykeys() {
	if ($("#fb_uid").length == 0) { return; }
	var user = $('#fb_uid').text().split(/\s*-\s*/);
	var pubkeys = get_pubkey(user[0]);
	var privkeys = get_privkey(user[0]);
	error('pubkey '+pubkeys[0].armored);
	$('#pubkey').val(pubkeys[0].armored);
	$('#privkey').val(privkeys[0].armored);
}

function import_keys() {
	try {
	}catch(e){error(e.message)}
}

function display_pubkey(user_search) {
try{
	if (!user_search) { user_search = $('#newuserid_txt').val() };
	error('search for key for '+user_search);
	var pubkeys = get_pubkey(user_search);
	error(user_search+' pubkey:\n'+pubkeys[0].armored);
	$('#pubkey').val(pubkeys[0].armored);
}catch(e) {
	error(e.message);
}
}

function newkeys() {
try{
	openpgp.init();
	var p1 = $('#pass1').val();
	var passphrase = $('#pass2').val();
	if (p1 != passphrase) {
		$('#newkeys_error').text('Your passphrases did not match.  Try again.');
		error('passphrase doesn\'t match.  try again.');
		return;
	} else if (p1 == '') {
		$('#newkeys_error').text('Please use a passphrase.');
		return;
	}
	$('#newkeys_error').text('');
	
	
	get_fb_uid(function(userid,userpath) {
		error('generate keypair for '+userid+' with passphrase '+passphrase);
		var obj = openpgp.generate_key_pair(1,2048,'fb_uid:'+userid+' fb_path:'+userpath,passphrase);
	
		error(JSON.stringify(obj));
	
		var js_obj_privkey = obj.privateKey;
		var privkey_text = obj.privateKeyArmored;
		var pubkey_text = obj.publicKeyArmored;
		
		error('pub\n'+pubkey_text);
		error('priv \n'+privkey_text);
		
		$('#privkey').val(privkey_text);
		$('#pubkey').val(pubkey_text);

		var p = import_privkey(passphrase);
		error(JSON.stringify(p));
	
		import_pubkey();
		openpgp.keyring.store();
	});

	$('#newkyes_error').html('Your new keys are below.  Make a copy and keep them safe.<br/>Save your public key to your facebook profile so others can send encrypted messages back to you!');

}catch(e){ error('newkeys '+e.message+' - '+JSON.stringify(e)) }
}


function require(script) {
    $.ajax({
        url: script,
        dataType: "script",
        async: false,           // <-- this is the key
        success: function () {
            // all good...
        },
        error: function (e) {
            throw new Error("Could not load script " + script+": "+e.message);
        }
    });
}

function error(str,ta) { 
	console.error(str);
	if (ta == 2) { str = '<textarea cols=40 rows=5>'+str+'</textarea>' }
	else if (ta) { str = '<textarea>'+str+'</textarea>'; }
	$('#debug').html(str+'\n<br>\n'+$('#debug').html())
}

function showMessages(str) {
	$('#debug').append(str);
}

function send_encrypted_text(encrypted) {
	do_send_all({"encrypted":encrypted},function(){});
}

function get_fb_uid(callback) {
	error('get_fb_uid');
	do_send_all({"get_fb_uid":true},function(r) {
		if (!r) {
			error('fb_uid response is undefined');
		} else if (r && r['fb_uid']) {
			error('get_fb_uid ok field: '+r['fb_uid']);
			$('#fb_uid').text(r['fb_uid']+' - '+r['fb_path']);
			if (callback) {
				callback(r['fb_uid'],r['fb_path']);
			}
		} else {
			error(JSON.stringify(r),1);
			error('problem with get_fb_uid');
		}
		return true;
	});
}

function fetch_text() {
	$('#mybutton').attr('disabled','disabled');
	do_send_all({"fetch_text":true},function(response) {
				error('fetch response OK '+JSON.stringify(response));
				if (response && response['message'] && response['message'] != '') {
					$('#message').val(response['message']);
					var txt_arr = new Array();
					var id_arr = new Array();
					var html_arr = new Array();
					for (var i=0;i<response['to'].length;i++) {
						txt_arr.push(response['to'][i]['text']);
						id_arr.push(response['to'][i]['path']);
						html_arr.push($('<span style="color:blue;" id="to_disp_'+response['to'][i]['path'].substr(1).replace(/\W/g,'')+'">'+response['to'][i]['text']+'</span><br/>'));
					}
					
					$('#encrypt_to').html(html_arr);
					$('#encrypt_to_ids').val(id_arr.join(','));
					key_count = id_arr.length;
					get_pubkey($('#encrypt_to_ids').val());
					key_timer = setInterval(function() { 
						if (key_count == 0) { 
							$('#mybutton').attr('disabled',false);
							$('#encrypt_error').html('enable encryption').css('color','rgb(0,255,0)');
							clearInterval(key_timer);
						}
						if (key_timer_iter++ > 120) {
							$('#encrypt_error').html('time out,cancelling encryption').css('color','rgb(255,0,0)');
							clearInterval(key_timer);
						}
						
					},500);
				}
				return true;
			});
}

function do_send_all(obj,callback) {
	error('do_send_all start');
	chrome.windows.getAll({'populate': true}, function(windows) {
    	for (var i = 0; i < windows.length; i++) {
	      var tabs = windows[i].tabs;
    	  for (var j = 0; j < tabs.length; j++) {
    	  	error('send to window '+i+' tab '+j+' id '+tabs[j].id);
    	  	try {
				chrome.tabs.sendMessage(tabs[j].id,obj,callback);
			}catch(e){}
		  }
		}
	});
	error('do_send_all done');
}


function initBackground(type) {
	openpgp.init();
	if (type != 'bg') {
		return true;
	}
   	loadContentScriptInAllTabs();
	
	console.log('init background');

  chrome.runtime.onMessage.addListener(
      function(request, sender, sendResponse) {
      	console.log('master message listener '+request);
      	console.log(JSON.stringify(request));
        if (request['message'] && request['to']) {
        	sendResponse({"encrypted": encrypt_message(request['message'],request['to'])});
        } else if (request['decrypt'] && request['passphrase']) {
        	get_fb_uid(function(fb_uid,fb_path) {
	        	var decrypted = decrypt(request['decrypt'],fb_uid,request['passphrase']);
	        	console.log('sending decrypted response '+JSON.stringify(decrypted));
	        	sendResponse(decrypted);
	        });
        } else {
        	error(JSON.stringify(request),1);
        	error('unknown request:');
        }
        return true;
      });
}


document.addEventListener('DOMContentLoaded',function() {
	openpgp.init();
	$('#newkeys_btn').click(function(){newkeys()});
	$('#mybutton').click(function(){encrypt()});
	$('#showkeys_btn').click(function(){showkeys()});
	$('#showmykeys_btn').click(function(){showmykeys()});
	$('#clearkeys_btn').click(function(){clearkeys()});
	$('#decrypt_btn').click(function(){decrypt($('#message').val(),false,$('#passphrase').val())});
	$('#add_keypair').click(function(){import_keys()});
	$('#fetch_text_btn').click(function(){fetch_text()});
	$('#clear_debug_btn').click(function(){$('#debug').text(' ');});
	$('#load_pubkey_btn').click(function(){display_pubkey()});
	$('#load_enc_pub_key_btn').click(function(){get_pubkey($('#encrypt_to_ids').val())});
	initBackground();
	get_fb_uid();

	return true;
});