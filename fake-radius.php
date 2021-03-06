#!/usr/bin/php -q
<?php
/**
 * Author: Jorge Pereira <jorge.pereira@mobicare.com.br>
 * Seguindo a rfc https://tools.ietf.org/html/rfc5176
 */
  
include("lib/fake_server.php");

if (!extension_loaded('radius')) {
  @die('radius extension required: ?? ln -fs /etc/php5/conf.d/radius.ini /etc/php5/cli/conf.d/90-radius.ini  ???');
}

/* config set */
$port = 1812;
$qtd = 1;
$secret = "testing123";

/* debug options */
error_reporting(E_ALL);

/* Allow the script to hang around waiting for connections. */
set_time_limit(0);

/* Turn on implicit output flushing so we see what we're getting
 * as it comes in. */
ob_implicit_flush();

/* codes and handlers */
$pack_types = array( /* Codes: Radius-Auth, rfc https://tools.ietf.org/html/rfc2865 */
                   1 => array("Access-Request",      "cb_access_request"),
                   2 => array("Access-Accept",       null),
                   3 => array("Access-Reject",       null),
                   4 => array("Accounting-Request",  "cb_acct_request"),
                   5 => array("Accounting-Response", null),
                  11 => array("Access-Challenge",    null ),

                  /* Codes: CoA rfc https://tools.ietf.org/html/rfc5176 */
                  40 => array("Disconnect-Request",  null),
                  41 => array("Disconnect-ACK",      null),
                  42 => array("Disconnect-NAK",      null),
                  43 => array("CoA-Request",         "cb_coa_request"),
                  44 => array("CoA-ACK",             null),
                  45 => array("CoA-NAK",             null),
);

function get_request_code($pkt_name) {
  GLOBAL $pack_types;

  foreach($pack_types as $var => $key) {
    if ($key[0] == $pkt_name)
      return $var;
  }
  return null;
}

function get_request_type($request) {
  GLOBAL $pack_types;
  
  if (@array_key_exists($request->code, $pack_types)) {
    $obj = new StdClass;

    $obj->name = $pack_types[$request->code][0];
    $obj->cb = $pack_types[$request->code][1];

    return $obj;
  } else {
    return null;
  }
}

$attributes = array(
                 1 => "User-Name",
                 2 => "User-Password",
                 4 => "NAS-IP-Address",
                 5 => "NAS-Port",
                25 => "Class"
);

/* helpers */
function dbg() {
  $arg = func_get_args();
  $arg[0] = sprintf("**dbg(): %s \n", $arg[0]);
  call_user_func_array("printf", $arg);
}

/* handlers */
function wrapper_envelope($client, $request, $code, $response = null) {
  GLOBAL $secret;

  $r = new RadiusResponse();
  $r->code = get_request_code($code);

  if (!empty($response)) {
    $r->attributes = array(
      @Attribute::expect(18 /*Reply-Message*/, $response),
    );
  }

  $body = $r->serialise($request, $secret);
  
  $ret = socket_sendto($client['sock'], $body, strlen($body), 0 , $client['ip'], $client['port']);
  if (!$ret) {  
    echo "socket_sendto(): failed: reason: " . socket_strerror(socket_last_error()) . "\n";
    return false;
  }
  return true;
}

/* handlers */
function cb_coa_request($client, $request) {
  $res = "CoA-ACK";

  dbg("[<<] Response the request with $res.");

  return wrapper_envelope($client, $request, "$res", "RADIUS::FAKE() Pacote $res OK");
}

function cb_access_request($client, $request) {
  $res = "Access-Accept";

  dbg("[<<] Response the request with $res.");

  return wrapper_envelope($client, $request, "$res", "RADIUS::FAKE() Pacote $res OK");
}

function cb_acct_request($client, $request) {
  $res = "Accounting-Response";

  dbg("[<<] Response the request with $res.");

  return wrapper_envelope($client, $request, "$res", "RADIUS::FAKE() Pacote $res OK");
}

/////////////////////////////////////////////////////////////////////////////////
// main()
/////////////////////////////////////////////////////////////////////////////////
if(($sock = socket_create(AF_INET, SOCK_DGRAM, SOL_UDP)) === false) {
    dbg("ERROR: socket_create() failed: reason: %s ", socket_strerror(socket_last_error()));
    exit(-1);
}

if(socket_bind($sock, "0", $port) === false) {
    dbg("ERROR: socket_bind() failed: reason: %s", socket_strerror(socket_last_error($sock)));
    exit(-1);
}

dbg("/* Iniciando Servidor RadiusFake {auth, coa} : na porta udp://$port */");

// busyloop()
do {
  $payload = null;
  $request = null;
  $client = array('sock' => $sock);

  dbg("Waiting requests.");

  if(!($socklen = socket_recvfrom ($sock, $payload, 512, 0, $client['ip'], $client['port']))) {
    dbg("WARNING: socket_read() failed: reason: " . socket_strerror(socket_last_error($msgsock)));
    break 2;
  }

  $request = @Request::parse($payload);
  //print_r($request); continue;

  // core
  $code = get_request_type($request);
  if(!$code) {
    dbg("WARNING: Receiving the invalid packet '%d' from %s:%d, ignoring.", $payload[0], $client['ip'], $client['port']);
    dump_hex($payload);
    continue;
  }
  
  dbg("[>>] Receiving the packet '%s' from %s:%d with identifier=%d length=%d, calling %s()",
            $code->name, $client['ip'], $client['port'], $request->id,
            strlen($request->raw), $code->cb
  );

  //dbg("<packet request>");
  //print_r($request->attributes);
  //dbg("</packet request>");

  if(!function_exists($code->cb)) {
    dbg("ERROR: The callback %s() don't exist, ignoring.\n", $code->cb);
    continue;
  }
  
  if(!call_user_func($code->cb, $client, $request)) {
    dbg("the callback %s() return false", $code->cb);
  }

  // continue
  $qtd++;
} while (true);

socket_close($sock);

echo "Quit\n";
?>
