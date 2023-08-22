/*

THESE NEXT LINES ARE CUSTOMIZABLE SETTINGS

*/

var invoicemac = "";
var adminmac = "";
var lndendpoint = ""; //e.g. https://127.0.0.1:8080 or https://cloud-59.voltage.com
var fee_type = "relative"; //alternative: "absolute"
var fee = 5; //if fee type is absolute, this integer is a flat rate, e.g. you will get 5 sats per swap; otherwise you get a rate corresponding to e.g. 5% of each swap

/*

END OF CUSTOMIZABLE SETTINGS - DON'T TOUCH ANYTHING AFTER THIS POINT

*/

var http = require( 'http' );
var url = require( 'url' );
var fs = require( 'fs' );
var crypto = require( 'crypto' );
var bitcoinjs = require('bitcoinjs-lib');
var varuintBitcoin = require( 'varuint-bitcoin' );
var request = require('request');
var { ECPairFactory } = require('ecpair');
var tinysecp = require('tiny-secp256k1');
var ECPair = ECPairFactory(tinysecp);
var bolt11 = require('bolt11');
var browserifyCipher = require('browserify-cipher');
var nobleSecp256k1 = require('noble-secp256k1');
var bech32 = require( 'bech32' );
var ws = require('websocket');
var WebSocketClient = ws.client;
var axios = require('axios');
var path = require('path');

var privKey = ECPair.makeRandom().privateKey.toString( "hex" );
var pubKeyMinus2 = nobleSecp256k1.getPublicKey( privKey, true ).substring( 2 );
console.log( "my privkey:", privKey );
console.log( "my pubkey:", pubKeyMinus2 );
var deal_in_progress = false;

function getData( url ) {
  return new Promise( function( resolve, reject ) {
    axios
    .get( url )
    .then( res => {
      resolve( res.data );
    }).catch( function( error ) {
      console.log( `axios error involving url ${url}:`, error.message );
    });
  });
}

function postData( url, json, headers ) {
  return new Promise( function( resolve, reject ) {
    axios
    .post( url, json, headers )
    .then( res => {
      resolve( res.data );
    }).catch( function( error ) {
      console.log( `axios error involving url ${url} and json ${json}:`, error.message );
    });
  });
}

function witnessStackToScriptWitness(witness) {
  let buffer2 = Buffer.allocUnsafe(0);
  function writeSlice(slice) {
    buffer2 = Buffer.concat([buffer2, Buffer.from(slice)]);
  }
  function writeVarInt(i) {
    const currentLen = buffer2.length;
    const varintLen = varuintBitcoin.encodingLength(i);
    buffer2 = Buffer.concat([buffer2, Buffer.allocUnsafe(varintLen)]);
    varuintBitcoin.encode(i, buffer2, currentLen);
  }
  function writeVarSlice(slice) {
    writeVarInt(slice.length);
    writeSlice(slice);
  }
  function writeVector(vector) {
    writeVarInt(vector.length);
    vector.forEach(writeVarSlice);
  }
  writeVector(witness);
  return buffer2;
}

async function getMinFeeRate( network ) {
  var fees = await getData( "https://mempool.space/" + network + "api/v1/fees/recommended" );
  if ( !( "hourFee" in fees ) ) return "error -- site down";
  var minfee = fees[ "hourFee" ];
  return minfee;
}

var destroyOldPendings = async () => {
  var current_blockheight = await getBlockheight( "" );
  Object.keys( users ).forEach( async user => {
    var i; for ( i=0; i<users[ user ][ "pending" ].length; i++ ) {
      var pending = users[ user ][ "pending" ][ i ];
      var index = i;
      var status = await checkInvoiceStatusWithoutLoop( pending[ "pmthash" ] );
      if ( status === "CANCELED" ) {
        console.log( "this pending is canceled:", pending[ "pmthash" ], "so I'm about to delete it. It belonged to this user:", user, "whose username is", users[ user ][ "username" ] );
        users[ user ][ "pending" ].splice( index, 1 );
        index = index - 1;
        continue;
      }
      if ( status === "SETTLED" ) {
        console.log( "this pending is settled:", pending[ "pmthash" ], "so I'm about to delete it. It belonged to this user:", user, "whose username is", users[ user ][ "username" ] );
        users[ user ][ "pending" ].splice( index, 1 );
        index = index - 1;
        continue;
      }
      if ( current_blockheight > pending[ "expires" ] + 12 ) {
        console.log( "this pending expires at this time:", pending[ "expires" ], "and the current blockheight is:", current_blockheight, "-- which is either higher than the pending's expiry (meaning it is expired) or fewer than 12 blocks lower (because", pending[ "expires" ], "minus", current_blockheight, "equals", pending[ "expires" ] - current_blockheight, "which is less than 12). So I'm about to delete it. Its hash was", pending[ "pmthash" ], "and it belonged to this user:", user, "whose username is", users[ user ][ "username" ] );
        users[ user ][ "pending" ].splice( index, 1 );
        index = index - 1;
        continue;
      }
    }
  });
  var texttowrite = JSON.stringify( users );
  fs.writeFileSync( "users.txt", texttowrite, function() {return;});
}

async function getBlockheight( network ) {
  var data = await getData( "https://mempool.space/" + network + "api/blocks/tip/height" );
  return Number( data );
}

var nostrTagIsValid = async ( event, amount ) => {
  if ( !isValidJson( event ) ) return;
  event = JSON.parse( event );
  if ( !( 'pubkey' in event ) || !( 'created_at' in event ) || !( 'kind' in event ) || !( 'tags' in event ) || !( 'content' in event ) ) {
      return;
  }
  //validate sig
  var serial_event = JSON.stringify([
    0,
    event['pubkey'],
    event['created_at'],
    event['kind'],
    event['tags'],
    event['content']
  ]);
  var id = sha256( serial_event );
  var sig = event.sig;
  var pubkey = event.pubkey;
  var sig_is_valid = await nobleSecp256k1.schnorr.verify( sig, id, pubkey );
  if ( !sig_is_valid ) return;
  //ensure there is a p tag
  var p_tag_exists = false;
  var multiple_p_tags_exist = false;
  var amount_tag_exists = false;
  var amount_tag_value = null;
  var a_tag_exists = false;
  var a_tag_value = null;
  event.tags.forEach( tag => {
    if ( typeof tag != "object" || !tag[ 0 ] ) return true;
    if ( tag[ 0 ] === "p" ) {
      if ( p_tag_exists ) multiple_p_tags_exist = true;
      p_tag_exists = true;
    }
    if ( tag[ 0 ] === "a" && tag[ 1 ] ) {
      a_tag_exists = true;
      a_tag_value = tag[ 1 ];
    }
    if ( tag[ 0 ] === "amount" && tag[ 1 ] ) {
      amount_tag_exists = true;
      amount_tag_value = tag[ 1 ];
    }
  });
  if ( !p_tag_exists || multiple_p_tags_exist ) return;
  //if amount tag exists, ensure it matches amount parameter
  var amount_tag_matches = true;
  if ( amount_tag_exists ) amount_tag_matches = ( amount_tag_value == amount );
  if ( !amount_tag_matches ) return;
  //if an a tag exists, ensure it is a valid nip-33 event coordinate
  var a_tag_is_valid = true;
  a_tag_exists = true;
  a_tag_value = "30023:f7234bd4c1394dda46d09f35bd384dd30cc552ad5541990f98844fb06676e9ca:abcd";
  if ( a_tag_exists ) {
    var a_array = a_tag_value.split( ":" );
    if ( a_array.length != 3 ) a_tag_is_valid = false;
    a_array.every( item => {
      if ( typeof item != "string" ) {
        a_tag_is_valid = false;
        return;
      }
      return true;
    });
    if ( isNaN( a_array[ 0 ] ) ) a_tag_is_valid = false;
    if ( !isValidHex( a_array[ 1 ] ) || a_array[ 1 ].length != 64 ) a_tag_is_valid = false;
  }
  if ( a_tag_is_valid ) return true;
}

function generateHtlc(serverPubkey, userPubkey, pmthash, timelock) {
  return bitcoinjs.script.fromASM(
    `
      OP_SIZE
      ${bitcoinjs.script.number.encode(32).toString('hex')}
      OP_EQUALVERIFY
      OP_SHA256
      ${pmthash}
      OP_EQUAL
      OP_IF
      ${userPubkey}
      OP_ELSE
      ${bitcoinjs.script.number.encode(timelock).toString('hex')}
      OP_CHECKLOCKTIMEVERIFY
      OP_DROP
      ${serverPubkey}
      OP_ENDIF
      OP_CHECKSIG
    `
    .trim()
    .replace(/\s+/g, ' ')
  );
}

function encrypt( privkey, pubkey, text ) {
  var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
  var iv = Uint8Array.from( crypto.randomBytes( 16 ) )
  var cipher = browserifyCipher.createCipheriv(
    'aes-256-cbc',
    Buffer.from( key, 'hex' ),
    iv
  );
  var encryptedMessage = cipher.update( text, "utf8", "base64" );
  var emsg = encryptedMessage + cipher.final( "base64" );
  return emsg + "?iv=" + Buffer.from( iv.buffer ).toString( "base64");
}

function decrypt( privkey, pubkey, ciphertext ) {
  var [ emsg, iv ] = ciphertext.split( "?iv=" );
  var key = nobleSecp256k1.getSharedSecret( privkey, '02' + pubkey, true ).substring( 2 );
  var decipher = browserifyCipher.createDecipheriv(
    'aes-256-cbc',
    Buffer.from( key, "hex" ),
    Buffer.from( iv, "base64" )
  );
  var decryptedMessage = decipher.update( emsg, "base64" );
  try {
    var dmsg = decryptedMessage + decipher.final( "utf8" );
  } catch( e ) {
    var dmsg = "error decrypting message -- either the message was malformed or it was not sent by me";
  }
  return dmsg;
}

var getUserByUsername = name => {
  var key = "";
  Object.keys( users ).every( user => {
    if ( users[ user ][ "username" ] == name ) {
      key = user;
      return;
    }
    return true;
  });
  return key;
}

var getPaymentByHash = hash => {
  var pmt = "";
  var idx = "";
  var i; for ( i=0; i<Object.keys( users ).length; i++ ) {
    var user = Object.keys( users )[ i ];
    users[ user ][ "pending" ].every( ( pending, index ) => {
      if ( pending[ "pmthash" ] === hash ) {
        pmt = pending;
        idx = index;
        return;
      }
      return true;
    });
    if ( pmt ) break;
  }
  return [pmt, idx];
}

async function getNostrNote( id, relay ) {
  var started_waiting_time = Math.floor( Date.now() / 1000 );
  var socket = new WebSocketClient();
  var note = "";
  var connected = false;
  socket.on( 'connect', function( connection ) {
    connected = true;
    connection.on( 'message', async function( event ) {
      var event = JSON.parse( event.utf8Data );
      if ( event[ 2 ] && event[ 2 ].kind != 1 ) {
        var i; for ( i=0; i<event[ 2 ].tags.length; i++ ) {
          if ( event[ 2 ].tags[ i ] && event[ 2 ].tags[ i ][ 1 ] ) {
            var recipient = event[ 2 ].tags[ i ][ 1 ];
            if ( event[ 2 ].pubkey == pubKeyMinus2 ) {
              note = decrypt( privKey, recipient, event[ 2 ].content );
            } else {
              note = decrypt( privKey, event[ 2 ].pubkey, event[ 2 ].content );
            }
          }
        }
      } else if ( event[ 2 ] && event[ 2 ].kind == 1 ) {
        note = ( event[ 2 ].content );
      }
    });
    var randomid = ECPair.makeRandom().privateKey.toString( "hex" ).substring( 0, 16 );
    var filter = {
      "ids": [
        id
      ]
    }
    var subscription = [ "REQ", randomid, filter ];
    subscription = JSON.stringify( subscription );
    var chaser = [ "CLOSE", randomid ];
    chaser = JSON.stringify( chaser );
    connection.sendUTF( subscription );
    setTimeout( function() {connection.sendUTF( chaser );}, 1000 );
    setTimeout( function() {connection.close();}, 2000 );
  });
  var connect_on_loop = async () => {
    if ( !connected ) {
      socket.connect( relay );
      await waitSomeSeconds( 1 );
      connect_on_loop();
    }
  }
  connect_on_loop();
  async function isNoteSetYet( note_i_seek ) {
    return new Promise( function( resolve, reject ) {
      if ( !note_i_seek ) {
        var current_time = Math.floor( Date.now() / 1000 );
        if ( started_waiting_time + 5 < current_time ) {
            resolve( "time is up" );
        }
        setTimeout( async function() {
          var msg = await isNoteSetYet( note );
          resolve( msg );
        }, 100 );
      } else {
        resolve( note_i_seek );
      }
    });
  }
  async function getTimeoutData() {
    var note_i_seek = await isNoteSetYet( note );
    return note_i_seek;
  }
  var returnable = await getTimeoutData();
  return returnable;
}

var makeEvent = async ( note, recipientpubkey ) => {
  var now = Math.floor( ( new Date().getTime() ) / 1000 );
  if ( recipientpubkey ) {
    note = encrypt( privKey, recipientpubkey, note );
    var newevent = [
      0,
      pubKeyMinus2,
      now,
      4,
      [['p', recipientpubkey]],
      note
    ];
  } else {
    var newevent = [
      0,
      pubKeyMinus2,
      now,
      1,
      [],
      note
    ];    
  }
  var message = JSON.stringify( newevent );
  var msghash = sha256( message );
  var sig = await nobleSecp256k1.schnorr.sign( msghash, privKey );
  var fullevent = {
    "id": msghash,
    "pubkey": pubKeyMinus2,
    "created_at": now,
    "kind": recipientpubkey ? 4 : 1,
    "tags": recipientpubkey ? [['p', recipientpubkey]] : [],
    "content": note,
    "sig": sig
  }
  return fullevent;
}

async function setNote( note, relay, recipientpubkey ) {
    var real_note = null;
    if ( typeof note == "object" ) {
      real_note = note;
      note = "dummy text";
    }
    var temp_socket = new WebSocketClient();
    var id = "";
    var connected = false;
    temp_socket.on( "error", function( error ) {
        console.log( "error:", error );
    });
    temp_socket.on( "connect", function( connection ) {
        connected = true;
        async function send( note, recipientpubkey ) {
            var fullevent = await makeEvent( note, recipientpubkey );
            if ( real_note ) fullevent = real_note;
            var sendable = [ "EVENT", fullevent ];
            sendable = JSON.stringify( sendable );
            connection.sendUTF( sendable );
            id = fullevent.id;
            setTimeout( function() {connection.close();}, 300 );
        }
        send( note, recipientpubkey, relay );
    });
    var connect_on_loop = async () => {
      if ( !connected ) {
        temp_socket.connect( relay );
        await waitSomeSeconds( 1 );
        connect_on_loop();
      }
    }
    connect_on_loop();
    temp_socket.connect( relay );
    async function isNoteSetYet( note_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( !note_i_seek ) {
                setTimeout( async function() {
                    var msg = await isNoteSetYet( id );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( note_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var note_i_seek = await isNoteSetYet( id );
        return note_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

var eventWasReplayedTilSeen = async ( event, the_relay, num ) => {
    if ( !num ) num = 0;
    var note = await getNostrNote( event.id, the_relay );
    if ( note != "time is up" ) return true;
    console.log( "replaying this event:", event.id, "at this relay:", the_relay );
    num = num + 1;
    await setNote( event, the_relay );
    var was_seen = false;
    if ( num < 6 ) was_seen = await eventWasReplayedTilSeen( event, the_relay, num );
    return was_seen;
}

function recoverSats( senderPrivkey, inputtxid, inputindex, fromamount, toaddress, toamount, sequence_number ) {
    var keyPairSender = ECPair.fromPrivateKey( Buffer.from( senderPrivkey, 'hex' ), bitcoinjs.networks.mainnet );
    var psbt = new bitcoinjs.Psbt({ network: bitcoinjs.networks.mainnet })
    .addInput({
        hash: inputtxid,
        index: inputindex,
        sequence: Number( sequence_number ),
        witnessUtxo: {
            script: Buffer.from( "0014" + bitcoinjs.crypto.ripemd160( bitcoinjs.crypto.sha256( keyPairSender.publicKey ) ).toString( "hex" ), "hex" ),
            value: fromamount,
        },
    })
    .addOutput({
        address: toaddress,
        value: toamount,
    });
    var getFinalScripts = ( txindex, input, script ) => {
        // Step 1: Check to make sure the meaningful locking script matches what you expect.
        var decompiled = bitcoinjs.script.decompile( script )
        if ( !decompiled ) {
            throw new Error( `Can not finalize input #${txindex}` )
        }

        // Step 2: Create final scripts
        var witnessStack = bitcoinjs.payments.p2wsh({
            redeem: {
                output: script,
                input: bitcoinjs.script.compile([
                    input.partialSig[0].signature,
                    Buffer.from( ECPair.makeRandom().privateKey.toString( "hex" ), "hex" ),
                 ]),
            }
        });
        return {
            finalScriptWitness: witnessStackToScriptWitness( witnessStack.witness )
        }
    }
    psbt.signInput( 0, ECPair.fromPrivateKey( Buffer.from( senderPrivkey, "hex" ) ) );
    psbt.finalizeInput( 0, getFinalScripts );
    return psbt.extractTransaction().toHex();
}

function getSwapAddress( serverPubkey, userPubkey, pmthash, timelock ) {
    var witnessscript = generateHtlc( serverPubkey, userPubkey, pmthash, timelock );
    var p2wsh = bitcoinjs.payments.p2wsh({redeem: {output: witnessscript, network: bitcoinjs.networks.mainnet}, network: bitcoinjs.networks.mainnet });
    return p2wsh.address;
}

function bytesToHex( bytes ) {
    return bytes.reduce( ( str, byte ) => str + byte.toString( 16 ).padStart( 2, "0" ), "" );
}

function sha256( string ) {
  return crypto.createHash( "sha256" ).update( string ).digest( "hex" );
}

function isValidJson( content ) {
    if ( !content ) return;
    try {  
        var json = JSON.parse( content );
    } catch ( e ) {
        return;
    }
    return true;
}

async function estimateExpiry( pmthash ) {
    //use the creation date of the invoice that pays me to estimate the block when that invoice was created
    //do that by getting the current unix timestamp, the current blockheight, and the invoice creation timestamp,
    var invoice_creation_timestamp = await getInvoiceCreationTimestamp( pmthash );
    invoice_creation_timestamp = Number( invoice_creation_timestamp );
    var current_unix_timestamp = Number( Math.floor( Date.now() / 1000 ) );
    var current_blockheight = await getBlockheight( "" );
    current_blockheight = Number( current_blockheight );
    //then subtract X units of 600 seconds from the current timestamp til it is less than the invoice creation timestmap,
    var units_of_600 = 0;
    var i; for ( i=0; i<1008; i++ ) {
        var interim_unix_timestamp = current_unix_timestamp - ( ( ( units_of_600 ) + 1 ) * 600 );
        units_of_600 = units_of_600 + 1
        if ( interim_unix_timestamp < invoice_creation_timestamp ) {
            break;
        }
    }
    //then subtract X from the current blockheight to get an estimated block when my invoice was created, then add 900 to it
    //assign the result to a variable called block_when_i_consider_the_invoice_that_pays_me_to_expire
    var block_when_i_consider_the_invoice_that_pays_me_to_expire = ( current_blockheight - units_of_600 ) + 900;
/*
    //get the current blockheight and, to it, add the cltv_expiry value of the invoice I am asked to pay (should be 40 usually)
    //assign the result to a variable called block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire
    var expiry_of_invoice_that_pays_me = await getInvoiceHardExpiry( pmthash );
    var expiry_of_invoice_i_am_asked_to_pay = await get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice );
    var block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire = current_blockheight + Number( expiry_of_invoice_i_am_asked_to_pay );
    //abort if block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire > block_when_i_consider_the_invoice_that_pays_me_to_expire
    if ( Number( block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire ) > Number( block_when_i_consider_the_invoice_that_pays_me_to_expire ) ) {
        return "nice try, asking me to pay you when the invoice that pays me is about to expire";
    }
    //because that would mean the recipient can hold my payment til after the invoice that pays me expires
    //then he could settle my payment to him but leave me unable to reimburse myself (because the invoice that pays me expired)
    //also, when sending my payment, remember to set the cltv_limit value
    //it should be positive and equal to block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight
    var cltv_limit = block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight;
*/
    var returnable = {}
    return block_when_i_consider_the_invoice_that_pays_me_to_expire;
}

async function makeInvoiceWithPreimage( amount, preimage ) {
  var invoice = "";
  var macaroon = invoicemac;
  var endpoint = lndendpoint + "/v1/invoices";
  let requestBody = {
      r_preimage: Buffer.from( preimage, "hex" ).toString( "base64" ),
      value: amount.toString()
  }
  let options = {
    url: endpoint,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify(requestBody),
  }
  request.post(options, function(error, response, body) {
    invoice = body[ "payment_request" ];
    console.log( "body:", body );
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( invoice );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( invoice );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function getHodlInvoice( amount, hash, expiry = 40, desc_hash ) {
  var invoice = "";
  var macaroon = invoicemac;
  var endpoint = lndendpoint + "/v2/invoices/hodl";
  let requestBody = {
      hash: Buffer.from( hash, "hex" ).toString( "base64" ),
      value: amount.toString(),
      cltv_expiry: expiry.toString(),
      description_hash: Buffer.from( desc_hash, "hex" ).toString( "base64" )
  }
  let options = {
    url: endpoint,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify(requestBody),
  }
  request.post(options, function(error, response, body) {
    invoice = body[ "payment_request" ];
    console.log( "hodl invoice:", body );
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( invoice );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( invoice );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function settleHoldInvoice( preimage ) {
  var settled = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let requestBody = {
      preimage: Buffer.from( preimage, "hex" ).toString( "base64" )
  }
  let options = {
    url: endpoint + '/v2/invoices/settle',
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify( requestBody ),
  }
  request.post( options, function( error, response, body ) {
    if ( body.toString().includes( "{" ) ) {
        settled = "true";
    } else {
        settled = "false";
    }
  });
  async function isNoteSetYet( note_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( note_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isNoteSetYet( settled );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( note_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var invoice_i_seek = await isNoteSetYet( settled );
            return invoice_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;   
}

async function howManyConfs( txid, network ) {
    var blockheight = await getBlockheight( network );
    return new Promise( async function( resolve, reject ) {
        var json = await getData( `https://blockstream.info/api/tx/` + txid );
        if ( json[ "status" ][ "confirmed" ] ) {
            resolve( ( Number( blockheight ) - Number( json[ "status" ][ "block_height" ] ) ) + 1 );
        } else {
            resolve( "0".toString() );
        }
    });
}

async function getAddress() {
  var address = "";
  var macaroon = invoicemac;
  var endpoint = lndendpoint + "/v2/wallet/address/next";
  let requestBody = {
    account: "",
    type: 1,
    change: false,
  };
  let options = {
    url: endpoint,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
    form: JSON.stringify(requestBody),
  }
  request.post(options, function(error, response, body) {
    address = body[ "addr" ];
  });
  async function isNoteSetYet( note_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( !note_i_seek ) {
                setTimeout( async function() {
                    var msg = await isNoteSetYet( address );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( note_i_seek );
            }
        });
    }
    async function getTimeoutData() {
            var address_i_seek = await isNoteSetYet( address );
            return address_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function addressOnceSentMoney( address ) {
    var json = await getData( "https://blockstream.info/api/address/" + address );
    if ( json[ "chain_stats" ][ "spent_txo_count" ] > 0 || json[ "mempool_stats" ][ "spent_txo_count" ] > 0 ) {
        return true;
    }
    return false;
}

async function getVout( txid, address, value, network ) {
    var vout = -1;
    var txinfo = await getData( `https://blockstream.info/${network}api/tx/${txid}` );
    txinfo[ "vout" ].every( function( output, index ) {
        if ( output[ "scriptpubkey_address" ] == address && output[ "value" ] == value ) {vout = index;return;} return true;
    });
    return vout;
}

async function loopTilAddressSendsMoney( address, recovery_info ) {
    var [ privkey, txid, vout, amount, confs_to_wait, recovery_address ] = recovery_info;
    //localStorage.content[ "privkey" ], txid_of_deposit, vout, Number( amount ), 40, recovery_address
    var itSpentMoney = false;
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( !data_i_seek ) {
                setTimeout( async function() {
                    //check how many confs the deposit tx has
                    var confs = await howManyConfs( txid, "" );
                    console.log( confs );
                    if ( Number( confs ) > 11 ) {
                        console.log( "time to sweep!" );
                        //sweep the deposit into the recovery address
                        var recovery_tx = recoverSats( privkey, txid, vout, amount, recovery_address, amount - 500, 40 );
                        await pushBTCpmt( recovery_tx, "" );
                        resolve( "recovered" );
                    }
                    console.log( "checking for preimage in mempool..." );
                    itSpentMoney = await addressOnceSentMoney( address );
                    var msg = await isDataSetYet( itSpentMoney );
                    resolve( msg );
                }, 2000 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( itSpentMoney );
        return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function addressSentMoneyInThisTx( address, txid_of_deposit ) {
    var txid;
    var json = await getData( "https://blockstream.info/api/address/" + address + "/txs" );
    json.forEach( function( tx ) {
        tx[ "vin" ].forEach( function( input ) {
            if ( input[ "txid" ] == txid_of_deposit ) {
                console.log( "txid that spent from the htlc:", tx[ "txid" ] );
                txid = tx[ "txid" ];
            }
        });
    });
    console.log( "double checking that I have the txid that spent from the htlc:", txid );
    return txid;
}

async function getPreimageFromTransactionThatSpendsAnHTLC( txid, pmthash ) {
    var json = await getData( "https://blockstream.info/api/tx/" + txid );
    var i; for ( i=0; i<json[ "vin" ].length; i++ ) {
        var j; for ( j=0; j<json[ "vin" ][ i ][ "witness" ].length; j++ ) {
            if ( bitcoinjs.crypto.sha256( Buffer.from( json[ "vin" ][ i ][ "witness" ][ j ], "hex" ) ).toString( "hex" ) == pmthash ) {
                console.log( "preimage I am passing in:", json[ "vin" ][ i ][ "witness" ][ j ] );
                console.log( "payment hash I am checking against:", pmthash );
                console.log( "payment hash I get when I hash the supposed preimage:", bitcoinjs.crypto.sha256( Buffer.from( json[ "vin" ][ i ][ "witness" ][ j ], "hex" ) ).toString( "hex" ) );
                return json[ "vin" ][ i ][ "witness" ][ j ];
            }
        }
    }
}

async function pushBTCpmt( rawtx, network ) {
    if ( !network ) network = "";
    var txid = await postData( "https://blockstream.info/" + network + "api/tx", rawtx );
    return txid;
}

async function paymentIsPending( invoice, amount ) {
    var users_pmthash = getinvoicepmthash( invoice );
    var state_of_held_invoice_with_that_hash = await checkInvoiceStatus( users_pmthash );
    if ( state_of_held_invoice_with_that_hash != "ACCEPTED" ) {
        deal_in_progress = false;
        return "nice try, asking me to pay an invoice without compensation: " + state_of_held_invoice_with_that_hash;
    }
    return true;
}

async function payInvoiceAndSettleWithPreimage( invoice ) {
    var preimage = "";
    var users_pmthash = getinvoicepmthash( invoice );
    var state_of_held_invoice_with_that_hash = await checkInvoiceStatusWithoutLoop( users_pmthash );
    if ( state_of_held_invoice_with_that_hash != "ACCEPTED" ) {
        return "nice try, asking me to pay an invoice without compensation: " + state_of_held_invoice_with_that_hash;
    }
    var amount_i_will_receive = await getInvoiceAmount( users_pmthash );
    var amount_i_am_asked_to_pay = get_amount_i_am_asked_to_pay( invoice );
    var feerate = await getMinFeeRate( "" );
    if ( fee_type === 'absolute' ) {
      var post_fee_amount = Number( amount_i_will_receive ) + fee;
    } else {
      var post_fee_amount = Number( amount_i_will_receive ) * ( ( 100 + fee ) / 100 );
    }
    post_fee_amount = Number( post_fee_amount.toFixed( 0 ) );
    var swap_fee = post_fee_amount - Number( amount_i_will_receive );
    if ( Number( amount_i_am_asked_to_pay ) > Number( amount_i_will_receive ) - swap_fee ) {
        return "nice try, asking me to send more than I will receive as compensation";
    }
    //use the creation date of the invoice that pays me to estimate the block when that invoice was created
    //do that by getting the current unix timestamp, the current blockheight, and the invoice creation timestamp,
    var invoice_creation_timestamp = await getInvoiceCreationTimestamp( users_pmthash );
    invoice_creation_timestamp = Number( invoice_creation_timestamp );
    var current_unix_timestamp = Number( Math.floor( Date.now() / 1000 ) );
    var current_blockheight = await getBlockheight( "" );
    current_blockheight = Number( current_blockheight );
    //then subtract X units of 600 seconds from the current timestamp til it is less than the invoice creation timestmap,
    var blocks_til_expiry = await getInvoiceHardExpiry( users_pmthash );
    blocks_til_expiry = Number( blocks_til_expiry );
    var units_of_600 = 0;
    var i; for ( i=0; i<blocks_til_expiry; i++ ) {
        var interim_unix_timestamp = current_unix_timestamp - ( ( ( units_of_600 ) + 1 ) * 600 );
        units_of_600 = units_of_600 + 1
        if ( interim_unix_timestamp < invoice_creation_timestamp ) {
            break;
        }
    }
    //then subtract X from the current blockheight to get an estimated block when my invoice was created, then add blocks_til_expiry to it
    //assign the result to a variable called block_when_i_consider_the_invoice_that_pays_me_to_expire
    var block_when_i_consider_the_invoice_that_pays_me_to_expire = ( current_blockheight - units_of_600 ) + blocks_til_expiry;
    //get the current blockheight and, to it, add the cltv_expiry value of the invoice I am asked to pay (should be 40 usually)
    //assign the result to a variable called block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire
    var expiry_of_invoice_that_pays_me = await getInvoiceHardExpiry( users_pmthash );
    var expiry_of_invoice_i_am_asked_to_pay = await get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice );
    var block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire = current_blockheight + Number( expiry_of_invoice_i_am_asked_to_pay );
    //abort if block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire > block_when_i_consider_the_invoice_that_pays_me_to_expire
    if ( Number( block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire ) > Number( block_when_i_consider_the_invoice_that_pays_me_to_expire ) ) {
        return "nice try, asking me to pay you when the invoice that pays me is about to expire";
    }
    //because that would mean the recipient can hold my payment til after the invoice that pays me expires
    //then he could settle my payment to him but leave me unable to reimburse myself (because the invoice that pays me expired)
    //also, when sending my payment, remember to set the cltv_limit value
    //it should be positive and equal to block_when_i_consider_the_invoice_that_pays_me_to_expire - current_blockheight
    var cltv_limit = Number( block_when_i_consider_the_invoice_that_pays_me_to_expire ) - current_blockheight;
    if ( cltv_limit < 40 ) return alert( "Oh no! The cltv limit was too low" );
    var adminmacaroon = adminmac;
    var endpoint = lndendpoint;
    var max_fee = swap_fee - 1;
    if ( max_fee > 500 ) max_fee = 500;
    let requestBody = {
        payment_request: invoice,
        fee_limit: {"fixed": String( max_fee )},
        allow_self_payment: true,
        cltv_limit: Number( cltv_limit )
    }
    let options = {
        url: endpoint + '/v1/channels/transactions',
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
          'Grpc-Metadata-macaroon': adminmacaroon,
        },
        form: JSON.stringify( requestBody ),
    }
    request.post( options, function( error, response, body ) {
        console.log( "here is the body:", body );
        if ( !body[ "payment_preimage" ] ) preimage = `error: ${body[ "payment_error" ]}`;
        else preimage = body[ "payment_preimage" ];
    });
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isDataSetYet( preimage );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( preimage );
        return data_i_seek;
    }
    var preimage_for_settling_invoice_that_pays_me = await getTimeoutData();
    if ( preimage_for_settling_invoice_that_pays_me != "" && !preimage_for_settling_invoice_that_pays_me.includes( "error" ) ) {
        preimage_for_settling_invoice_that_pays_me = Buffer.from( preimage_for_settling_invoice_that_pays_me, "base64" ).toString( "hex" );
        console.log( "preimage that pays me:", preimage_for_settling_invoice_that_pays_me );
        settleHoldInvoice( preimage_for_settling_invoice_that_pays_me );
        returnable = '{"status": "success","preimage":"' + preimage_for_settling_invoice_that_pays_me + '"}';
        destroyOldPendings();
    } else {
        returnable = '{"status": "failure"}';
    }
    deal_in_progress = false;
    return returnable;
}

async function payHTLCAndSettleWithPreimage( invoice, htlc_address, amount ) {
    var txid_of_deposit = "";
    var users_pmthash = getinvoicepmthash( invoice );
    var amount_i_will_receive = await getInvoiceAmount( users_pmthash );
    var amount_i_am_asked_to_pay = get_amount_i_am_asked_to_pay( invoice );
    if ( Number( amount_i_will_receive ) < Number( amount_i_am_asked_to_pay ) ) {
        return "nice try, asking me to send more than I will receive as compensation";
    }
    //use the creation date of the invoice that pays me to estimate the block when that invoice was created
    //do that by getting the current unix timestamp, the current blockheight, and the invoice creation timestamp,
    var invoice_creation_timestamp = await getInvoiceCreationTimestamp( users_pmthash );
    invoice_creation_timestamp = Number( invoice_creation_timestamp );
    var current_unix_timestamp = Number( Math.floor( Date.now() / 1000 ) );
    var current_blockheight = await getBlockheight( "" );
    current_blockheight = Number( current_blockheight );
    //then subtract X units of 600 seconds from the current timestamp til it is less than the invoice creation timestamp,
    var units_of_600 = 0;
    var i; for ( i=0; i<1008; i++ ) {
        var interim_unix_timestamp = current_unix_timestamp - ( ( ( units_of_600 ) + 1 ) * 600 );
        units_of_600 = units_of_600 + 1
        if ( interim_unix_timestamp < invoice_creation_timestamp ) {
            break;
        }
    }
    //then subtract X from the current blockheight to get an estimated block when my invoice was created, then add 900 to it
    //assign the result to a variable called block_when_i_consider_the_invoice_that_pays_me_to_expire
    var block_when_i_consider_the_invoice_that_pays_me_to_expire = ( current_blockheight - units_of_600 ) + 900;
    //get the current blockheight and, to it, add the cltv_expiry value of the invoice I am asked to pay (should be 40 usually)
    //assign the result to a variable called block_when_i_consider_the_invoice_i_am_asked_to_pay_to_expire
    var expiry_of_invoice_that_pays_me = await getInvoiceHardExpiry( users_pmthash );
    var adminmacaroon = adminmac;
    var endpoint = lndendpoint;
    var feerate = await getMinFeeRate( "" );
    if ( fee_type === 'absolute' ) {
      var post_fee_amount = Number( amount ) + fee;
    } else {
      var post_fee_amount = Number( amount ) * ( ( 100 + fee ) / 100 );
    }
    post_fee_amount = Number( post_fee_amount.toFixed( 0 ) );
    var swap_fee = post_fee_amount - Number( amount );
    let requestBody = {
        addr: htlc_address,
        amount: String( Number( amount ) - swap_fee - ( feerate * 200 ) ),
        sat_per_byte: String( feerate )
    }
    let options = {
        url: endpoint + '/v1/transactions',
        // Work-around for self-signed certificates.
        rejectUnauthorized: false,
        json: true,
        headers: {
          'Grpc-Metadata-macaroon': adminmacaroon,
        },
        form: JSON.stringify( requestBody ),
    }
    request.post( options, function( error, response, body ) {
        txid_of_deposit = ( body[ "txid" ] );
        console.log( "body:", body );
        console.log( "txid_of_deposit:", txid_of_deposit );
    });
    async function isDataSetYet( data_i_seek ) {
        return new Promise( function( resolve, reject ) {
            if ( data_i_seek == "" ) {
                setTimeout( async function() {
                    var msg = await isDataSetYet( txid );
                    resolve( msg );
                }, 100 );
            } else {
                resolve( data_i_seek );
            }
        });
    }
    async function getTimeoutData() {
        var data_i_seek = await isDataSetYet( txid );
        return data_i_seek;
    }
    //while looping, if address doesn't send money before timelock expires, I sweep money back to myself
    //to do that, I send the privkey (localStorage.content[ "privkey" ]), the txid (txid_of_deposit),
    //the output number, the value of the deposit (Number( amount )), the number of confs to wait (40), and an address obtained from lnd to loopTilAddressSendsMoney. Then, when that function loops, it checks
    //how many confs the deposit tx has, and, if it has more than 40, sweeps the money to the address
    //obtained from lnd
    await waitSomeSeconds( 30 );
    var vout = await getVout( txid_of_deposit, htlc_address, Number( amount ), "" );
    console.log( "vout:", vout );
    var recovery_address = await getAddress();
    var recovery_info = [permakey, txid_of_deposit, vout, Number( amount ), 40, recovery_address];
    var itSentMoney = await loopTilAddressSendsMoney( htlc_address, recovery_info );
    if ( itSentMoney == "recovered" ) {
        return '{"status": "failure", "reason": "The buyer never swept their money so we swept it back"}';
    }
    console.log( "moving on" );
    await waitSomeSeconds( 3 );
    var txid_that_sweeps_htlc = await addressSentMoneyInThisTx( htlc_address, txid_of_deposit );
    await waitSomeSeconds( 3 );
    var preimage_for_settling_invoice_that_pays_me = await getPreimageFromTransactionThatSpendsAnHTLC( txid_that_sweeps_htlc, users_pmthash );
    if ( preimage_for_settling_invoice_that_pays_me != "" ) {
        //preimage_for_settling_invoice_that_pays_me = Buffer.from( preimage_for_settling_invoice_that_pays_me, "base64" ).toString( "hex" );
        console.log( "preimage that pays me:", preimage_for_settling_invoice_that_pays_me );
        settleHoldInvoice( preimage_for_settling_invoice_that_pays_me );
        destroyOldPendings();
        var returnable = '{"status": "success","preimage":"' + preimage_for_settling_invoice_that_pays_me + '"}';
    } else {
        var returnable = '{"status": "failure"}';
    }
    console.log( "deal is in progress, right?", deal_in_progress );
    deal_in_progress = false;
    console.log( "what about now? It is in progress, right? (I actually don't want it to be)", deal_in_progress );
    return returnable;
}

function waitSomeSeconds( num ) {
    var num = num.toString() + "000";
    num = Number( num );
    return new Promise( function( resolve, reject ) {
        setTimeout( function() { resolve( "" ); }, num );
    });
}

function isValidInvoice( invoice ) {
    try{
        return ( typeof( bolt11.decode( invoice ) ) == "object" );
    } catch( e ) {
        return;
    }
}

function get_amount_i_am_asked_to_pay( invoice ) {
    var decoded = bolt11.decode( invoice );
    var amount = decoded[ "satoshis" ].toString();
    return amount;
}

async function getInvoiceAmount( hash ) {
  var amount = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    amount = body[ "value" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( amount );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( amount );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkInvoiceStatusWithoutLoop( hash ) {
  var status = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    status = body[ "state" ];
    console.log( "status:", status );
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( status );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( status );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function checkInvoiceStatus( hash ) {
  var status = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    status = body[ "state" ];
    console.log( "status:", status );
  });
  var time = 0;
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek != "ACCEPTED" ) {
                          setTimeout( async function() {
                                  time = time + 1;
                                  console.log( "time:", time )
                                  if ( time == 36000 || time > 36000 ) {
                                    resolve( "failure" );
                                    return;
                                  }
                                  console.log( "checking if buyer sent payment yet..." );
                                  status = await checkInvoiceStatusWithoutLoop( hash );
                                  var msg = await isDataSetYet( status );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( status );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function getInvoiceCreationTimestamp( hash ) {
  var timestamp = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    timestamp = body[ "creation_date" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( timestamp );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( timestamp );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function getInvoiceHardExpiry( hash ) {
  var expiry = "";
  const macaroon = invoicemac;
  const endpoint = lndendpoint;
  let options = {
    url: endpoint + '/v1/invoice/' + hash,
    // Work-around for self-signed certificates.
    rejectUnauthorized: false,
    json: true,
    headers: {
      'Grpc-Metadata-macaroon': macaroon,
    },
  }
  request.get( options, function( error, response, body ) {
    expiry = body[ "cltv_expiry" ];
  });
  async function isDataSetYet( data_i_seek ) {
          return new Promise( function( resolve, reject ) {
                  if ( data_i_seek == "" ) {
                          setTimeout( async function() {
                                  var msg = await isDataSetYet( expiry );
                                  resolve( msg );
                          }, 100 );
                  } else {
                          resolve( data_i_seek );
                  }
          });
    }
    async function getTimeoutData() {
            var data_i_seek = await isDataSetYet( expiry );
            return data_i_seek;
    }
    var returnable = await getTimeoutData();
    return returnable;
}

async function get_hard_expiry_of_invoice_i_am_asked_to_pay( invoice ) {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "min_final_cltv_expiry" ) {
            var cltv_expiry = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return cltv_expiry;
}

function getinvoicepmthash( invoice ) {
    var decoded = bolt11.decode( invoice );
    var i; for ( i=0; i<decoded[ "tags" ].length; i++ ) {
        if ( decoded[ "tags" ][ i ][ "tagName" ] == "payment_hash" ) {
            var pmthash = decoded[ "tags" ][ i ][ "data" ].toString();
        }
    }
    return pmthash;
}

function isValidHex( h ) {
  if ( !h ) return;
  var length = h.length;
  if ( length % 2 ) return;
  try {
    var a = BigInt( "0x" + h, "hex" );
  } catch( e ) {
    return;
  }
  var unpadded = a.toString( 16 );
  var padding = [];
  var i; for ( i=0; i<length; i++ ) padding.push( 0 );
  padding = padding.join( "" );
  padding = padding + unpadded.toString();
  padding = padding.slice( -Math.abs( length ) );
  return ( padding === h );
}

if ( fs.existsSync( "users.txt" ) ) {
  var dbtext = fs.readFileSync( "users.txt" ).toString();
  var users = JSON.parse( dbtext );
} else {
  var users = {}
  var texttowrite = JSON.stringify( users );
  fs.writeFileSync( "users.txt", texttowrite, function() {return;});
  var dbtext = fs.readFileSync( "users.txt" ).toString();
  var users = JSON.parse( dbtext );
}

var permakey = "";
var permapub = "";

if ( fs.existsSync( "privkey.txt" ) ) {
  permakey = fs.readFileSync( "privkey.txt" ).toString();
  permapub = nobleSecp256k1.getPublicKey( permakey, true );
} else {
  permakey = Buffer.from( nobleSecp256k1.utils.randomPrivateKey() ).toString( "hex" );
  permapub = nobleSecp256k1.getPublicKey( permakey, true );
  fs.writeFileSync( "privkey.txt", permakey, function() {return;});
}

var allowed_routes = [
  "/test_username",
  "/test_pubkey",
  "/set_user",
  "/.well-known/lnurlp/",
  "/lnurlp/pay/",
  "/start_swap",
  "/wallet",
  "/custom_invoice",
  "/check_invoice",
  "/pay_invoice"
];

var sendResponse = ( response, data, statusCode, content_type ) => {
  if ( response.finished ) return;
  response.setHeader( 'Access-Control-Allow-Origin', '*' );
  response.setHeader( 'Access-Control-Request-Method', '*' );
  response.setHeader( 'Access-Control-Allow-Methods', 'OPTIONS, GET' );
  response.setHeader( 'Access-Control-Allow-Headers', '*' );
  response.setHeader( 'Content-Type', content_type[ "Content-Type" ] );
  response.writeHead( statusCode );
  response.end( data );
};

var collectData = ( request, callback ) => {
  var data = '';
  request.on( 'data', ( chunk ) => {
    data += chunk;
  });
  request.on( 'end', () => {
    callback( data );
  });
};

const requestListener = async function( request, response ) {
  destroyOldPendings();
  var protocol = request.connection.encrypted ? 'https': 'http';
  if ( request.headers[ "x-forwarded-proto" ] == "https" ) protocol = "https";
  var realUrl = protocol + '://' + request.headers.host + request.url;
  var parts = url.parse( realUrl, true );
  var $_GET = parts.query;
  var page_exists = false;
  allowed_routes.every( route => {
    if ( parts.path.startsWith( route ) || parts.path == "/" || parts.path == "" ) {
      page_exists = true;
      return;
    }
    return true;
  });
  if ( !page_exists ) {
    sendResponse( response, 'Page not found', 404, {'Content-Type': 'text/plain'} );
    return;
  }
  if ( request.method === 'GET' ) {
    if ( parts.path.startsWith( "/pay_invoice" ) ) {
      if ( !$_GET[ "invoice" ] || !isValidInvoice( $_GET[ "invoice" ] ) ) {
        sendResponse( response, 'error: invalid invoice', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      var status = await payInvoiceAndSettleWithPreimage( $_GET[ "invoice" ] );
      destroyOldPendings();
      sendResponse( response, status, 200, {'Content-Type': 'application/json'} );
      return;
    }
    if ( parts.path === "/" ) {
      var filePath = path.join(__dirname, 'index.html');
      var stat = fs.statSync(filePath);
      response.writeHead(200, {
          'Content-Type': 'text/html',
          'Content-Length': stat.size
      });
      var readStream = fs.createReadStream(filePath);
      readStream.pipe(response);
      return;
    }
    if ( parts.path.startsWith( "/custom_invoice" ) ) {
      if ( !$_GET[ "preimage" ] || !$_GET[ "amount" ] ) {
        sendResponse( response, 'error: invalid invoice details', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      if ( !isValidHex( $_GET[ "preimage" ] ) || isNaN( $_GET[ "amount" ] ) ) {
        sendResponse( response, 'error: invalid invoice details', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      if ( $_GET[ "preimage" ].length != 64 || Number( $_GET[ "amount" ] ) < 1 ) {
        sendResponse( response, 'error: invalid invoice details', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      var invoice = await makeInvoiceWithPreimage( Number( $_GET[ "amount" ] ), $_GET[ "preimage" ] );
      console.log( "invoice:", invoice );
      sendResponse( response, invoice, 200, {'Content-Type': 'text/plain'} );
      return;
    }
    if ( parts.path.startsWith( "/check_invoice" ) ) {
      var invoice = $_GET[ "invoice" ];
      var pmthash = getinvoicepmthash( invoice );
      var status = await checkInvoiceStatusWithoutLoop( pmthash );
      if ( status == "SETTLED" ) {
        sendResponse( response, "settled", 200, {'Content-Type': 'text/plain'} );
        return;
      } else {
        sendResponse( response, "waiting", 200, {'Content-Type': 'text/plain'} );
        return;
      }
    }
    if ( parts.path.startsWith( "/wallet" ) ) {
      var filePath = path.join(__dirname, 'wallet.html');
      var stat = fs.statSync(filePath);
      response.writeHead(200, {
          'Content-Type': 'text/html',
          'Content-Length': stat.size
      });
      var readStream = fs.createReadStream(filePath);
      readStream.pipe(response);
      return;
    }
    if ( parts.path.startsWith( "/start_swap" ) ) {
      if ( !$_GET[ "swap_pubkey" ] || !$_GET[ "htlc_address" ] || !$_GET[ "pmthash" ] ) {
        sendResponse( response, 'error: invalid swap details', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      var pmt = getPaymentByHash( $_GET[ "pmthash" ] )[ 0 ];
      var idx = getPaymentByHash( $_GET[ "pmthash" ] )[ 1 ];
      if ( !pmt || pmt[ "status" ] != "ready" ) {
        sendResponse( response, 'error: invalid swap details', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      users[ pmt[ "user_pubkey" ] ][ "pending" ][ idx ].status = "swap_in_progress";
      var texttowrite = JSON.stringify( users );
      fs.writeFileSync( "users.txt", texttowrite, function() {return;});
      var current_blockheight = await getBlockheight( "" );
      var timelock = current_blockheight + 10;
      var witness_script = generateHtlc(
        pmt[ "serverPubkey" ],
        $_GET[ "swap_pubkey" ],
        $_GET[ "pmthash" ],
        timelock
      );
      var htlcObject = bitcoinjs.payments.p2wsh({
        redeem: {
          output: witness_script,
          network: bitcoinjs.networks.mainnet,
        },
        network: bitcoinjs.networks.mainnet,
      });
      if ( htlcObject.address != $_GET[ "htlc_address" ] ) {
        sendResponse( response, 'error: invalid swap details', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      payHTLCAndSettleWithPreimage( pmt[ "swap_invoice" ], htlcObject.address, pmt[ "amount" ] );
    }
    if ( parts.path.startsWith( "/test_pubkey" ) ) {
      if ( !$_GET[ "pubkey" ] || !Object.keys( users ).includes( $_GET[ "pubkey" ] ) ) {
        sendResponse( response, 'error: invalid pubkey', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      sendResponse( response, JSON.stringify( users[ $_GET[ "pubkey" ] ] ), 200, {'Content-Type': 'application/json'} );
      return;
    }
    if ( parts.path.startsWith( "/test_username" ) ) {
      if ( !$_GET[ "username" ] ) {
        sendResponse( response, 'error: no username', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      var username = $_GET[ "username" ];
      username = username.toLowerCase();
      var name_exists = false;
      Object.keys( users ).every( user => {
        if ( users[ user ][ "username" ] == username ) {
          name_exists = true;
          return;
        }
        return true;
      });
      if ( name_exists ) {
        sendResponse( response, 'error: username taken', 200, {'Content-Type': 'text/plain'} );
      } else {
        sendResponse( response, 'all is well', 200, {'Content-Type': 'text/plain'} );
      }
    }
    if ( parts.path.startsWith( "/.well-known/lnurlp/" ) ) {
      var username = parts.path.substring( parts.path.indexOf( "/.well-known/lnurlp/" ) + 20 );
      username = username.toLowerCase();
      var name_exists = false;
      Object.keys( users ).every( user => {
        if ( users[ user ][ "username" ] == username ) {
          name_exists = true;
          return;
        }
        return true;
      });
      if ( !username || username.includes( "/" ) || !name_exists ) {
        sendResponse( response, `error: this username is unknown: ${username}`, 200, {'Content-Type': 'text/plain'} );
        return;
      }
      var feerate = await getMinFeeRate( "" );
      if ( fee_type === 'absolute' ) {
        var min = Math.floor( 546 + fee + ( ( feerate * 200 ) * 2 ) );
      } else {
        var min = Math.floor( ( 546 + ( ( feerate * 200 ) * 2 ) ) / ( 1 - ( fee / 100 ) ) );
      }
      var json = {
        "callback":`${"https://" + parts.hostname}/lnurlp/pay/${username}`,
        "minSendable":min * 1000,
        "maxSendable":9007199254740991,
        "metadata":`[[\"text/plain\",\"Paying ${username}\"],[\"text/identifier\",\"${username}@${parts.hostname}\"]]`,
        "tag":"payRequest",
        // "nostrPubkey":"00009483d5e84e8850e5430654e61802fd2838cdf0ffa8fe774b4e9a63f52428",
        // "allowsNostr":true
      }
      sendResponse( response, JSON.stringify( json ), 200, {'Content-Type': 'application/json; charset=utf-8'} );
    }
    if ( parts.path.startsWith( "/lnurlp/pay/" ) ) {
      var json = {"status": "ERROR", "reason": "invalid amount"}
      var feerate = await getMinFeeRate( "" );
      if ( fee_type === 'absolute' ) {
        var min = Math.floor( 546 + fee + ( ( feerate * 200 ) * 2 ) );
      } else {
        var min = Math.floor( ( 546 + ( ( feerate * 200 ) * 2 ) ) / ( 1 - ( fee / 100 ) ) );
      }
      if ( !$_GET || !$_GET[ "amount" ] || isNaN( $_GET[ "amount" ] ) || !parts.path.includes( "?amount=" ) || Math.round( Number( $_GET[ "amount" ] ) / 1000 ) < min ) {
        sendResponse( response, JSON.stringify( json ), 200, {'Content-Type': 'application/json'} );
        return;
      }
      var nostr_tag_exists_and_is_valid = false;
      var nostr_event = null;
      if ( $_GET[ "nostr" ] ) {
        nostr_tag_exists_and_is_valid = await nostrTagIsValid( $_GET[ "nostr" ], $_GET[ "amount" ] );
      }
      var amount = Math.round( Number( $_GET[ "amount" ] ) / 1000 );
      console.log( amount, min, amount < min )
      var username = parts.path.substring( parts.path.indexOf( "/lnurlp/pay/" ) + 12, parts.path.indexOf( "?" ) );
      var name_exists = false;
      Object.keys( users ).every( user => {
        if ( users[ user ][ "username" ] == username ) {
          name_exists = true;
          return;
        }
        return true;
      });
      if ( !username || username.includes( "/" ) || !name_exists ) {
        sendResponse( response, 'error: username unknown', 200, {'Content-Type': 'text/plain'} );
        return;
      }
      var index_of_first_unused_pmthash;
      var user_pubkey = getUserByUsername( username );
      users[ user_pubkey ][ "this_users_hashes" ].every( ( hash, index ) => {
        if ( !hash[ 1 ] ) {
          index_of_first_unused_pmthash = index;
          return;
        }
        return true;
      });
      var desc = `[[\"text/plain\",\"Paying ${username}\"],[\"text/identifier\",\"${username}@${parts.hostname}\"]]`;
      if ( nostr_tag_exists_and_is_valid ) {
        desc = $_GET[ "nostr" ];
        nostr_event = $_GET[ "nostr" ];
      }
      var desc_hash = sha256( desc );
      var pmthash = users[ user_pubkey ][ "this_users_hashes" ][ index_of_first_unused_pmthash ][ 0 ];
      console.log( amount );
      var swap_invoice = await getHodlInvoice( amount, pmthash, 100, desc_hash );
      if ( !swap_invoice ) {
        deal_in_progress = false;
        return;
      }
      users[ user_pubkey ][ "this_users_hashes" ][ index_of_first_unused_pmthash ][ 1 ] = 1;
      var texttowrite = JSON.stringify( users );
      fs.writeFileSync( "users.txt", texttowrite, function() {return;});
      json = {
        pr: swap_invoice,
        routes: [],
        pmthash_sig: users[ user_pubkey ][ "sigs" ].match(/.{1,128}/g)[ index_of_first_unused_pmthash ],
        user_pubkey: user_pubkey,
      }
      sendResponse( response, JSON.stringify( json ), 200, {'Content-Type': 'application/json; charset=utf-8'} );
      var payment_is_pending = await paymentIsPending( swap_invoice, amount );
      //notify the recipient that it's time to settle their payment
      var event = await makeEvent( `This is your lightning address. You have a pending payment for ${amount} sats. Come to ${parts.hostname} to collect it, it will expire in 16 hours.`, user_pubkey );
      var was_seen = await eventWasReplayedTilSeen( event, users[ user_pubkey ][ "relay" ] );
      console.log( "the event was seen, right?", was_seen );
      //add an entry to the user's pending payments
      //make it say what the amount is and when the invoice is expected to expire
      //(which I can get using the getInvoiceHardExpiry() function) -- that way when
      //the user shows up to collect, I can easily give them the info they need to
      //construct the htlc so they can get their money
      var expires = await getInvoiceHardExpiry( pmthash );
      if ( fee_type === 'absolute' ) {
        var post_fee_amount = amount + fee;
      } else {
        var post_fee_amount = amount * ( ( 100 + fee ) / 100 );
      }
      post_fee_amount = Number( post_fee_amount.toFixed( 0 ) );
      var swap_fee = post_fee_amount - amount;
      var current_blockheight = await getBlockheight( "" );
      expires = Number( expires ) + Number( current_blockheight );
      users[ user_pubkey ][ "pending" ].push({expires, amount, pmthash, serverPubkey: permapub, swap_invoice, swap_fee, status: "ready", user_pubkey});
      var texttowrite = JSON.stringify( users );
      fs.writeFileSync( "users.txt", texttowrite, function() {return;});
      //todo: use nostr to give a zap receipt if the payment was a zap
    }
  } else if ( request.method === 'POST' ) {
    collectData(request, async ( formattedData ) => {
      if ( parts.path.startsWith( "/set_user" ) ) {
        var is_valid_json = isValidJson( formattedData );
        if ( !is_valid_json ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        var json = JSON.parse( formattedData );
        if ( Object.keys( json ).length != 6 ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        if ( !( "username" in json ) || !( "hashes" in json ) || !( "user_pubkey" in json ) || !( "relay" in json ) || !( "ciphertext" in json ) || !( "sigs" in json ) ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        if ( typeof json[ "username" ] != "string" || json[ "username" ].length > 64 ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        if ( typeof json[ "hashes" ] != "string" || json[ "hashes" ].length != 64000 ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        if ( typeof json[ "user_pubkey" ] != "string" || json[ "user_pubkey" ].length != 64 || !isValidHex( json[ "user_pubkey" ] ) ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        if ( typeof json[ "relay" ] != "string" || json[ "relay" ].length < 10 || !json[ "relay" ].startsWith( "wss://" ) ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        if ( typeof json[ "sigs" ] != "string" || json[ "sigs" ].length != 128000 ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        var name_exists = false;
        Object.keys( users ).every( user => {
          if ( users[ user ][ "username" ] == $_GET[ "username" ] ) {
            name_exists = true;
            return;
          }
          return true;
        });
        if ( name_exists ) {
          sendResponse( response, 'error: invalid json', 200, {'Content-Type': 'text/plain'} );
          return;
        }
        var this_users_hashes = [];
        var this_users_sigs = [];
        var submitted_hashes = json[ "hashes" ].match(/.{1,64}/g);
        var submitted_sigs = json[ "sigs" ].match(/.{1,128}/g);
        var i; for ( i=0; i<submitted_hashes.length; i++ ) {
          var hash = submitted_hashes[ i ];
          var index = i;
          var sig_is_good = await nobleSecp256k1.schnorr.verify( submitted_sigs[ index ], hash, json[ "user_pubkey" ] );
          if ( !sig_is_good ) {
            console.log( `oh no! A sig didn't match. Sig: ${submitted_sigs[ index ]} Hash: ${hash} Key: ${json[ "user_pubkey" ]}`);
            return;
          }
          this_users_hashes.push( [ hash, 0 ] );
        }
        users[ json[ "user_pubkey" ] ] = {
          username: json[ "username" ],
          relay: json[ "relay" ],
          this_users_hashes,
          pending: [],
          sigs: json[ "sigs" ],
          ciphertext: json[ "ciphertext" ],
        }
        var texttowrite = JSON.stringify( users );
        fs.writeFileSync( "users.txt", texttowrite, function() {return;});
        sendResponse( response, 'user created', 200, {'Content-Type': 'text/plain'} );
      }
    });
  }
};

const server = http.createServer( requestListener );
server.listen( 8081 );
